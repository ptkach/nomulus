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

package google.registry.model.contact;

import static google.registry.util.CollectionUtils.nullToEmptyImmutableCopy;

import com.google.common.collect.ImmutableList;
import google.registry.model.Buildable;
import google.registry.model.ImmutableObject;
import google.registry.model.UnsafeSerializable;
import google.registry.model.eppcommon.PresenceMarker;
import google.registry.persistence.converter.PostalInfoChoiceListUserType;
import jakarta.persistence.Embeddable;
import jakarta.persistence.Embedded;
import jakarta.xml.bind.annotation.XmlAttribute;
import jakarta.xml.bind.annotation.XmlType;
import java.io.Serializable;
import java.util.List;
import org.hibernate.annotations.Type;

/** The "discloseType" from <a href="http://tools.ietf.org/html/rfc5733">RFC5733</a>. */
@Embeddable
@XmlType(propOrder = {"name", "org", "addr", "voice", "fax", "email"})
public class Disclose extends ImmutableObject implements UnsafeSerializable {

  @Type(PostalInfoChoiceListUserType.class)
  List<PostalInfoChoice> name;

  @Type(PostalInfoChoiceListUserType.class)
  List<PostalInfoChoice> org;

  @Type(PostalInfoChoiceListUserType.class)
  List<PostalInfoChoice> addr;

  @Embedded PresenceMarker voice;

  @Embedded PresenceMarker fax;

  @Embedded PresenceMarker email;

  @XmlAttribute
  Boolean flag;

  public ImmutableList<PostalInfoChoice> getNames() {
    return nullToEmptyImmutableCopy(name);
  }

  public ImmutableList<PostalInfoChoice> getOrgs() {
    return nullToEmptyImmutableCopy(org);
  }

  public ImmutableList<PostalInfoChoice> getAddrs() {
    return nullToEmptyImmutableCopy(addr);
  }

  public PresenceMarker getVoice() {
    return voice;
  }

  public PresenceMarker getFax() {
    return fax;
  }

  public PresenceMarker getEmail() {
    return email;
  }

  public Boolean getFlag() {
    return flag;
  }

  /** The "intLocType" from <a href="http://tools.ietf.org/html/rfc5733">RFC5733</a>. */
  public static class PostalInfoChoice extends ImmutableObject implements Serializable {
    @XmlAttribute
    PostalInfo.Type type;

    public PostalInfo.Type getType() {
      return type;
    }

    public static PostalInfoChoice create(PostalInfo.Type type) {
      PostalInfoChoice instance = new PostalInfoChoice();
      instance.type = type;
      return instance;
    }
  }

  /** A builder for {@link Disclose} since it is immutable. */
  public static class Builder extends Buildable.Builder<Disclose> {
    public Builder setNames(ImmutableList<PostalInfoChoice> names) {
      getInstance().name = names;
      return this;
    }

    public Builder setOrgs(ImmutableList<PostalInfoChoice> orgs) {
      getInstance().org = orgs;
      return this;
    }

    public Builder setAddrs(ImmutableList<PostalInfoChoice> addrs) {
      getInstance().addr = addrs;
      return this;
    }

    public Builder setVoice(PresenceMarker voice) {
      getInstance().voice = voice;
      return this;
    }

    public Builder setFax(PresenceMarker fax) {
      getInstance().fax = fax;
      return this;
    }

    public Builder setEmail(PresenceMarker email) {
      getInstance().email = email;
      return this;
    }

    public Builder setFlag(boolean flag) {
      getInstance().flag = flag;
      return this;
    }
  }
}
