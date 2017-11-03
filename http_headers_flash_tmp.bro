# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# Contributor(s):
# Michal Purzynski mpurzynski@mozilla.com

# Detect browser plugins as they leak through requests to some 
# advertising servers.
# Scripts inspired by the original Bro code - policy/protocols/http/software-browser-plugins

@load base/protocols/http
@load base/frameworks/software
@load policy/protocols/http/software-browser-plugins

module HTTP;

event http_header(c: connection, is_orig: bool, name: string, value: string)
{
    if ( ! is_orig )
        return;
	if ( ! c?$http )
		return;

	if ( name == "X-REQUESTED-WITH" && /^ShockwaveFlash/ in value )
        Software::found(c$id, [$unparsed_version=value, $host=c$id$orig_h, $software_type=BROWSER_PLUGIN]);
}

