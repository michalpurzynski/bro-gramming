module ConnAnomaly;

type Val: record {
    wl_src: subnet;
    wl_dst: subnet;
    wl_port: port &type_column="t";
    wl_comment: string &optional;
};

global wl_dlp_table: table[subnet] of table[subnet] of set[port] = table() &synchronized;

event line(description: Input::EventDescription, tpe: Input::Event, value: Val)
{
    if (tpe != Input::EVENT_REMOVED) {
        if (value$wl_src !in wl_dlp_table) {
            wl_dlp_table[value$wl_src] = table();
        }
        if (value$wl_dst !in wl_dlp_table[value$wl_src]) {
            wl_dlp_table[value$wl_src][value$wl_dst] = set();
        }
        if (value$wl_port !in wl_dlp_table[value$wl_src][value$wl_dst]) {
            add wl_dlp_table[value$wl_src][value$wl_dst][value$wl_port];
        }
    } else {
        delete wl_dlp_table[value$wl_src][value$wl_dst];
    }
}

event bro_init()
{
    Input::add_event([$source="/opt/bro/share/bro/brozilla/dlp_input.txt",
            $name="wl_dlp_table_input",
            $fields=Val,
            $ev=line,
            $mode=Input::REREAD]);
}

