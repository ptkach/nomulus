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

package google.registry.module.backend;

import google.registry.request.RequestHandler;
import google.registry.request.auth.RequestAuthenticator;
import jakarta.inject.Inject;
import jakarta.inject.Provider;

/** Request handler for the backend module. */
public class BackendRequestHandler extends RequestHandler<BackendRequestComponent> {

  @Inject BackendRequestHandler(
      Provider<BackendRequestComponent.Builder> componentBuilderProvider,
      RequestAuthenticator requestAuthenticator) {
    super(componentBuilderProvider, requestAuthenticator);
  }
}
