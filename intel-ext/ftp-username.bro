# Copyright (c) 2015 CrowdStrike 2014
# josh.liburdi@crowdstrike.com
# Modifications and bugs by:
# Michal Purzynski mpurzynski@mozilla.com
#
# This file has been initially imported from https://github.com/CrowdStrike/NetworkDetection/tree/master/bro-scripts/intel-extensions/seen
#
# Intel framework support for FTP usernames 

@load base/protocols/ftp
@load base/frameworks/intel
@load policy/frameworks/intel/seen/where-locations

@load base/frameworks/intel

module Intel;

export {
  redef enum Intel::Where += {
    FTP::IN_USER_NAME,
  };
}

event ftp_request(c: connection, command: string, arg: string)
{
if ( command == "USER" )
 Intel::seen([$indicator=arg,
              $indicator_type=Intel::USER_NAME,
              $conn=c,
              $where=FTP::IN_USER_NAME]);
}
