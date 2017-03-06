/*
 * Copyright 2016 Igor Moochnick
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package certs

var Certs = map[string]string{
	"dev_Ca": `-----BEGIN CERTIFICATE-----
	...
	plug your cert here
	...
	-----END CERTIFICATE-----
	`,
		"dev_Client_cert": `-----BEGIN CERTIFICATE-----
	...
	plug your cert here
	...
	-----END CERTIFICATE-----
	`,
	"dev_Client_cert_key": `-----BEGIN CERTIFICATE-----
	...
	plug your cert here
	...
	-----END CERTIFICATE-----
	`,
	"stg_Ca": `-----BEGIN CERTIFICATE-----
	...
	plug your cert here
	...
	-----END CERTIFICATE-----
	`,
	"stg_Client_cert": `-----BEGIN CERTIFICATE-----
	...
	plug your cert here
	...
	-----END CERTIFICATE-----
	`,
	"stg_Client_cert_key": `-----BEGIN CERTIFICATE-----
	...
	plug your cert here
	...
	-----END CERTIFICATE-----
	`,
	"prod_Ca": `-----BEGIN CERTIFICATE-----
	...
	plug your cert here
	...
	-----END CERTIFICATE-----
	`,
	"prod_Client_cert": `-----BEGIN CERTIFICATE-----
	...
	plug your cert here
	...
	-----END CERTIFICATE-----
	`,
	"prod_Client_cert_key": `-----BEGIN CERTIFICATE-----
	...
	plug your cert here
	...
	-----END CERTIFICATE-----
	`,
}
