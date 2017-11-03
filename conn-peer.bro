##! Add the peer to the connection logs.

module Conn;

export {
    redef record Conn::Info += {
        peer: string &optional &log;
    };
}

event connection_state_remove(c: connection) {
    c$conn$peer = peer_description;
}
