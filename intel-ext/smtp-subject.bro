# Copyright (c) 2015 CrowdStrike 2014
# josh.liburdi@crowdstrike.com
#
# This file has been initially imported from https://github.com/CrowdStrike/NetworkDetection/tree/master/bro-scripts/intel-extensions/seen
#
# Intel framework support for SMTP subjects 

@load base/protocols/smtp
@load base/frameworks/intel
@load policy/frameworks/intel/seen/where-locations

@load base/frameworks/intel

module Intel;

export {
  redef enum Intel::Type += {
    EMAIL_SUBJECT
  };

  redef enum Intel::Where += {
    SMTP::IN_SUBJECT,
  };
}

event smtp_request(c: connection, is_orig: bool, command: string, arg: string) 
{
if ( c$smtp?$subject )
  Intel::seen([$indicator=c$smtp$subject,
               $indicator_type=Intel::EMAIL_SUBJECT,
               $conn=c,
               $where=SMTP::IN_SUBJECT]);
}
