# Extract files of specific MIME types
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# Contributor(s):
# Someone who originally wrote this script, I didn't

global ext_map: table[string] of string = {
	["application/x-dosexec"] = "exe",
	["application/octet-stream"] = "bin",
} &default ="";

event file_new(f: fa_file)
{
	local am_i_orig: bool;
	local ext = "";

	for (cid in f$conns) {
		if (Site::is_local_addr(cid$orig_h)) {
			am_i_orig = T;
			break;
		}
	}

	if (!f?$mime_type)
		f$mime_type = "application/octet-stream";
	if ( f?$mime_type && f$mime_type in ext_map)
		ext = ext_map[f$mime_type];

	local fname = fmt("/nsm/bro/extracted/%s-%s.%s", f$source, f$id, ext);
	Files::add_analyzer(f, Files::ANALYZER_EXTRACT, [$extract_filename=fname]);
}
