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

import google.registry.model.eppcommon.AuthInfo;
import jakarta.persistence.Embeddable;
import jakarta.xml.bind.annotation.XmlType;

/** A version of authInfo specifically for contacts. */
@Embeddable
@XmlType(namespace = "urn:ietf:params:xml:ns:contact-1.0")
public class ContactAuthInfo extends AuthInfo {
  public static ContactAuthInfo create(PasswordAuth pw) {
    ContactAuthInfo instance = new ContactAuthInfo();
    instance.pw = pw;
    return instance;
  }
}
