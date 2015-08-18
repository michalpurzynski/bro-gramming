# Script to detect certs issued by internal Mozilla CA before than 2014-04-11 00:00:00 CA time
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# Software distributed under the License is distributed on an "AS IS" basis,
# WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
# for the specific language governing rights and limitations under the
# License.
#
# The Initial Developer of the Original Code is
# Mozilla Corporation
# Portions created by the Initial Developer are Copyright (C) 2014
# the Initial Developer. All Rights Reserved.
#
# Contributor(s):
# Anthony Verez netantho@gmail.com

@load base/frameworks/notice
@load base/protocols/ssl

module HeartbleedMozillaCA;

export {
    redef enum Notice::Type += {
        HeartbleedMozillaCA_NeedChangeCert
    };
}

event x509_certificate(c: connection, is_orig: bool, cert: X509, chain_idx: count, chain_len: count, der_cert: string) &priority=3   
{
    # 2014-04-11 00:00:00 CA time
    local time_before = 1397199600.0;

    if (/[mM][oO][zZ][iI][lL][lL][aA]/ in cert$issuer && time_before > time_to_double(cert$not_valid_before)) {
        NOTICE([$note=HeartbleedMozillaCA_NeedChangeCert,
                $conn=c, $suppress_for=15mins,
                $msg=fmt("Moz CA-signed Certificate %s has not been changed after Heartbleed (valid since %T)", cert$subject, cert$not_valid_before),
                $identifier=cat(c$id$resp_h, c$id$resp_p, c$ssl$cert_hash)]);
    }
}

