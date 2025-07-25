// Copyright 2017 The Nomulus Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package google.registry.rdap;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.net.HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN;
import static google.registry.request.Actions.getPathForAction;
import static google.registry.util.DomainNameUtils.canonicalizeHostname;
import static jakarta.servlet.http.HttpServletResponse.SC_BAD_REQUEST;
import static jakarta.servlet.http.HttpServletResponse.SC_INTERNAL_SERVER_ERROR;
import static jakarta.servlet.http.HttpServletResponse.SC_NOT_FOUND;
import static jakarta.servlet.http.HttpServletResponse.SC_OK;
import static java.nio.charset.StandardCharsets.UTF_8;

import com.google.common.collect.Streams;
import com.google.common.flogger.FluentLogger;
import com.google.common.net.MediaType;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import google.registry.config.RegistryConfig.Config;
import google.registry.model.EppResource;
import google.registry.model.registrar.Registrar;
import google.registry.rdap.RdapMetrics.EndpointType;
import google.registry.rdap.RdapObjectClasses.ErrorResponse;
import google.registry.rdap.RdapObjectClasses.ReplyPayloadBase;
import google.registry.rdap.RdapObjectClasses.TopLevelReplyObject;
import google.registry.rdap.RdapSearchResults.BaseSearchResponse;
import google.registry.request.Action;
import google.registry.request.HttpException;
import google.registry.request.Parameter;
import google.registry.request.RequestMethod;
import google.registry.request.RequestPath;
import google.registry.request.RequestUrl;
import google.registry.request.Response;
import google.registry.util.Clock;
import jakarta.inject.Inject;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Optional;
import org.joda.time.DateTime;

/**
 * Base RDAP action for all requests.
 *
 * @see <a href="https://tools.ietf.org/html/rfc9082">RFC 9082: Registration Data Access Protocol
 *     (RDAP) Query Format</a>
 */
public abstract class RdapActionBase implements Runnable {

  private static final FluentLogger logger = FluentLogger.forEnclosingClass();

  private static final MediaType RESPONSE_MEDIA_TYPE =
      MediaType.create("application", "rdap+json").withCharset(UTF_8);

  private static final Gson GSON = new GsonBuilder().disableHtmlEscaping().create();
  private static final Gson FORMATTED_OUTPUT_GSON =
      new GsonBuilder().disableHtmlEscaping().setPrettyPrinting().create();

  /** Whether to include or exclude deleted items from a query. */
  protected enum DeletedItemHandling {
    EXCLUDE,
    INCLUDE
  }

  @Inject Response response;
  @Inject @RequestMethod Action.Method requestMethod;
  @Inject @RequestPath String requestPath;
  @Inject @RequestUrl String requestUrl;
  @Inject RdapAuthorization rdapAuthorization;
  @Inject RdapJsonFormatter rdapJsonFormatter;
  @Inject @Parameter("includeDeleted") Optional<Boolean> includeDeletedParam;
  @Inject @Parameter("formatOutput") Optional<Boolean> formatOutputParam;
  @Inject @Config("rdapResultSetMaxSize") int rdapResultSetMaxSize;
  @Inject RdapMetrics rdapMetrics;
  @Inject Clock clock;

  /** Builder for metric recording. */
  final RdapMetrics.RdapMetricInformation.Builder metricInformationBuilder =
      RdapMetrics.RdapMetricInformation.builder();

  private final String humanReadableObjectTypeName;

  /** Returns a string like "domain name" or "nameserver", used for error strings. */
  final String getHumanReadableObjectTypeName() {
    return humanReadableObjectTypeName;
  }

  /** The endpoint type used for recording metrics. */
  private final EndpointType endpointType;

  /** Returns the servlet action path; used to extract the search string from the incoming path. */
  final String getActionPath() {
    return getPathForAction(getClass());
  }

  RdapActionBase(String humanReadableObjectTypeName, EndpointType endpointType) {
    this.humanReadableObjectTypeName = humanReadableObjectTypeName;
    this.endpointType = endpointType;
  }

  /**
   * Does the actual search and returns an RDAP JSON object.
   *
   * RFC7480 4.1 - we have to support GET and HEAD.
   *
   * @param pathSearchString the search string in the URL path
   * @param isHeadRequest whether the returned map will actually be used. HTTP HEAD requests don't
   *        actually return anything. However, we usually still want to go through the process of
   *        building a map, to make sure that the request would return a 500 status if it were
   *        invoked using GET. So this field should usually be ignored, unless there's some
   *        expensive task required to create the map which will never result in a request failure.
   * @return A map (probably containing nested maps and lists) with the final JSON response data.
   */
  abstract ReplyPayloadBase getJsonObjectForResource(
      String pathSearchString, boolean isHeadRequest);

  @Override
  public void run() {
    metricInformationBuilder.setIncludeDeleted(includeDeletedParam.orElse(false));
    metricInformationBuilder.setRole(rdapAuthorization.role());
    metricInformationBuilder.setRequestMethod(requestMethod);
    metricInformationBuilder.setEndpointType(endpointType);
    // RFC7480 4.2 - servers receiving an RDAP request return an entity with a Content-Type header
    // containing the RDAP-specific JSON media type.
    response.setContentType(RESPONSE_MEDIA_TYPE);
    // RDAP Technical Implementation Guide 1.14 - when responding to RDAP valid requests, we MUST
    // include the Access-Control-Allow-Origin, which MUST be "*" unless otherwise specified.
    response.setHeader(ACCESS_CONTROL_ALLOW_ORIGIN, "*");
    try {
      // Extract what we're searching for from the request path. Some RDAP commands use trailing
      // data in the path itself (e.g. /rdap/domain/mydomain.com), and some use the query string
      // (e.g. /rdap/domains?name=mydomain); the query parameters are extracted by the subclasses
      // directly as needed.
      URI uri = new URI(requestPath);
      String pathProper = uri.getPath();
      checkArgument(
          pathProper.startsWith(getActionPath()),
          "%s doesn't start with %s", pathProper, getActionPath());
      String pathSearchString = pathProper.substring(getActionPath().length());
      logger.atInfo().log("path search string: '%s'.", pathSearchString);

      ReplyPayloadBase replyObject =
          getJsonObjectForResource(pathSearchString, requestMethod == Action.Method.HEAD);
      if (replyObject instanceof BaseSearchResponse) {
        metricInformationBuilder.setIncompletenessWarningType(
            ((BaseSearchResponse) replyObject).incompletenessWarningType());
      }
      // RFC7480 5.1 - if the server has the information requested and wishes to respond, it returns
      // that answer in the body of a 200 (OK) response
      response.setStatus(SC_OK);
      setPayload(replyObject);
      metricInformationBuilder.setStatusCode(SC_OK);
    } catch (RdapDomainAction.DomainBlockedByBsaException e) {
      logger.atInfo().withCause(e).log("Domain blocked by BSA");
      setErrorCodes(SC_NOT_FOUND);
      setPayload(new RdapObjectClasses.DomainBlockedByBsaErrorResponse(e.getMessage()));
    } catch (HttpException e) {
      logger.atInfo().withCause(e).log("Error in RDAP.");
      setError(e.getResponseCode(), e.getResponseCodeString(), e.getMessage());
    } catch (URISyntaxException | IllegalArgumentException e) {
      logger.atInfo().withCause(e).log("Bad request in RDAP.");
      setError(SC_BAD_REQUEST, "Bad Request", "Not a valid " + getHumanReadableObjectTypeName());
    } catch (RuntimeException e) {
      setError(SC_INTERNAL_SERVER_ERROR, "Internal Server Error", "An error was encountered");
      logger.atSevere().withCause(e).log("Exception encountered while processing RDAP command.");
    }
    rdapMetrics.updateMetrics(metricInformationBuilder.build());
  }

  void setError(int status, String title, String description) {
    setErrorCodes(status);
    try {
      setPayload(ErrorResponse.create(status, title, description));
    } catch (Exception ex) {
      logger.atSevere().withCause(ex).log("Failed to create an error response.");
      response.setPayload("");
    }
  }

  void setErrorCodes(int status) {
    metricInformationBuilder.setStatusCode(status);
    response.setStatus(status);
  }

  void setPayload(ReplyPayloadBase replyObject) {
    if (requestMethod == Action.Method.HEAD) {
      return;
    }
    TopLevelReplyObject topLevelObject =
        TopLevelReplyObject.create(replyObject, rdapJsonFormatter.createTosNotice());
    Gson gson = formatOutputParam.orElse(false) ? FORMATTED_OUTPUT_GSON : GSON;
    JsonObject jsonResult = topLevelObject.toJson();
    addLinkValuesRecursively(jsonResult);
    response.setPayload(gson.toJson(jsonResult));
  }

  /**
   * Returns true if the query should include deleted items.
   *
   * <p>This is true only if the request specified an includeDeleted parameter of true, AND is
   * eligible to see deleted information. Admins can see all deleted information, while
   * authenticated registrars can see only their own deleted information. Note that if this method
   * returns true, it just means that some deleted information might be viewable. If this is a
   * registrar request, the caller must still verify that the registrar can see each particular item
   * by calling {@link RdapAuthorization#isAuthorizedForRegistrar}.
   */
  boolean shouldIncludeDeleted() {
    // If includeDeleted is not specified, or set to false, we don't need to go any further.
    if (!includeDeletedParam.orElse(false)) {
      return false;
    }
    // Return true if we *might* be allowed to view any deleted info, meaning we're either an admin
    // or have access to at least one registrar's data
    return rdapAuthorization.role() == RdapAuthorization.Role.ADMINISTRATOR
        || !rdapAuthorization.registrarIds().isEmpty();
  }

  DeletedItemHandling getDeletedItemHandling() {
    return shouldIncludeDeleted() ? DeletedItemHandling.INCLUDE : DeletedItemHandling.EXCLUDE;
  }

  /**
   * Returns true if the request is authorized to see the resource.
   *
   * <p>This is true if the resource is not deleted, or the request wants to see deleted items, and
   * is authorized to do so.
   */
  boolean isAuthorized(EppResource eppResource) {
    return getRequestTime().isBefore(eppResource.getDeletionTime())
        || (shouldIncludeDeleted()
            && rdapAuthorization.isAuthorizedForRegistrar(
                eppResource.getPersistedCurrentSponsorRegistrarId()));
  }

  /**
   * Returns true if the registrar should be visible.
   *
   * <p>This is true iff: The resource is active and publicly visible, or the request wants to see
   * deleted items, and is authorized to do so
   */
  boolean isAuthorized(Registrar registrar) {
    return (registrar.isLiveAndPubliclyVisible()
        || (shouldIncludeDeleted()
            && rdapAuthorization.isAuthorizedForRegistrar(registrar.getRegistrarId())));
  }

  String canonicalizeName(String name) {
    name = canonicalizeHostname(name);
    if (name.endsWith(".")) {
      name = name.substring(0, name.length() - 1);
    }
    return name;
  }

  /** Returns the DateTime this request took place. */
  DateTime getRequestTime() {
    return rdapJsonFormatter.getRequestTime();
  }

  /**
   * Adds a request-referencing "value" to each link object.
   *
   * <p>This is the "context URI" as described in RFC 8288. Basically, this contains a reference to
   * the request URL that generated this RDAP response.
   *
   * <p>This is required per the RDAP February 2024 response profile sections 2.6.3 and 2.10, and
   * the technical implementation guide sections 3.2 and 3.3.2.
   *
   * <p>We must do this here (instead of where the links are generated) because many of the links
   * (e.g. terms of service) are static constants, and thus cannot by default know what the request
   * URL was.
   */
  private void addLinkValuesRecursively(JsonElement jsonElement) {
    if (jsonElement instanceof JsonArray jsonArray) {
      jsonArray.forEach(this::addLinkValuesRecursively);
    } else if (jsonElement instanceof JsonObject jsonObject) {
      if (jsonObject.get("links") instanceof JsonArray linksArray) {
        addLinkValues(linksArray);
      }
      jsonObject.entrySet().forEach(entry -> addLinkValuesRecursively(entry.getValue()));
    }
  }

  private void addLinkValues(JsonArray linksArray) {
    Streams.stream(linksArray)
        .map(JsonElement::getAsJsonObject)
        .filter(o -> !o.has("value"))
        .forEach(o -> o.addProperty("value", requestUrl));
  }
}
