// Copyright 2024 The Nomulus Authors. All Rights Reserved.
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

import { Component, computed } from '@angular/core';
import { RegistrarService } from 'src/app/registrar/registrar.service';
import { RdapService } from './rdap.service';

@Component({
  selector: 'app-rdap',
  templateUrl: './rdap.component.html',
  styleUrls: ['./rdap.component.scss'],
  standalone: false,
})
export default class RdapComponent {
  public static PATH = 'rdap';
  formattedAddress = computed(() => {
    let result = '';
    const registrar = this.registrarService.registrar();
    if (registrar?.localizedAddress?.street) {
      result += `${registrar?.localizedAddress?.street?.join(' ')} `;
    }
    if (registrar?.localizedAddress?.city) {
      result += `${registrar?.localizedAddress?.city} `;
    }
    if (registrar?.localizedAddress?.state) {
      result += `${registrar?.localizedAddress?.state} `;
    }
    if (registrar?.localizedAddress?.countryCode) {
      result += `${registrar?.localizedAddress?.countryCode} `;
    }
    if (registrar?.localizedAddress?.zip) {
      result += registrar?.localizedAddress?.zip;
    }
    return result;
  });

  constructor(
    public rdapService: RdapService,
    public registrarService: RegistrarService
  ) {}
}
