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

package google.registry.flows;

import static google.registry.util.CollectionUtils.nullToEmpty;

import jakarta.servlet.http.HttpSession;
import java.util.Optional;
import java.util.Set;

/** A metadata class that is a wrapper around {@link HttpSession}. */
public class HttpSessionMetadata extends SessionMetadata {

  private static final String REGISTRAR_ID = "REGISTRAR_ID";
  private static final String SERVICE_EXTENSIONS = "SERVICE_EXTENSIONS";
  private static final String FAILED_LOGIN_ATTEMPTS = "FAILED_LOGIN_ATTEMPTS";

  private final HttpSession session;

  public HttpSessionMetadata(HttpSession session) {
    this.session = session;
  }

  @Override
  public void invalidate() {
    session.invalidate();
  }

  @Override
  public String getRegistrarId() {
    return (String) session.getAttribute(REGISTRAR_ID);
  }

  @Override
  @SuppressWarnings("unchecked")
  public Set<String> getServiceExtensionUris() {
    return nullToEmpty((Set<String>) session.getAttribute(SERVICE_EXTENSIONS));
  }

  @Override
  public int getFailedLoginAttempts() {
    return Optional.ofNullable((Integer) session.getAttribute(FAILED_LOGIN_ATTEMPTS)).orElse(0);
  }

  @Override
  public void setRegistrarId(String registrarId) {
    session.setAttribute(REGISTRAR_ID, registrarId);
  }

  @Override
  public void setServiceExtensionUris(Set<String> serviceExtensionUris) {
    session.setAttribute(SERVICE_EXTENSIONS, serviceExtensionUris);
  }

  @Override
  public void incrementFailedLoginAttempts() {
    session.setAttribute(FAILED_LOGIN_ATTEMPTS, getFailedLoginAttempts() + 1);
  }

  @Override
  public void resetFailedLoginAttempts() {
    session.removeAttribute(FAILED_LOGIN_ATTEMPTS);
  }
}
