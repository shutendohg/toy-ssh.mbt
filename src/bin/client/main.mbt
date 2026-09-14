///|
/// Toy SSH client, M2 scope: connects, completes the key exchange, sends
/// SERVICE_REQUEST ssh-userauth, and exits 0 once SERVICE_ACCEPT arrives.
/// User authentication is M3.
///
/// Usage: client [--connect 127.0.0.1:2222]
///
/// M2 limitation: any host key is accepted (its fingerprint is printed);
/// known_hosts handling is M3 (docs/05).
///
/// Toy code. Never use for real security.

///|
async fn main raise {
  let args = @env.args()
  let mut target = "127.0.0.1:2222"
  let mut i = 1
  while i < args.length() {
    match args[i] {
      "--connect" => {
        target = args[i + 1]
        i = i + 2
      }
      other => {
        println("unknown argument: \{other}")
        @sys.exit(2)
      }
    }
  }
  let addr = @socket.Addr::parse(target)
  let conn = @socket.Tcp::connect(addr)
  defer conn.close()
  println("toy-ssh client: connected to \{addr}")
  let mut exit_code = 1
  let cfg = @net.client_config(accept_host_key=k_s => {
    println("toy-ssh client: server host key blob \{@hex.encode(k_s[:])} (accepted: M2 has no known_hosts)")
    true
  })
  let t = @transport.Transport::new(cfg)
  @net.run(conn, t, (t, ev) => match ev {
    Established(session_id~) => {
      println("toy-ssh client: established, session id \{@hex.encode(session_id[:])}")
      t.send_packet(
        @transport.encode_service_request(@transport.SERVICE_USERAUTH)[:],
      )
    }
    Packet(payload~) => {
      let service = @transport.decode_service_accept(payload[:]) catch {
        _ => {
          println("toy-ssh client: unexpected message \{payload[0].to_int()}")
          t.disconnect(@transport.SSH_DISCONNECT_PROTOCOL_ERROR, "unexpected message")
          return
        }
      }
      println("toy-ssh client: SERVICE_ACCEPT \{service}; userauth is M3, done")
      exit_code = 0
      t.disconnect(@transport.SSH_DISCONNECT_BY_APPLICATION, "toy-ssh M2 demo complete")
    }
    Disconnect(code~, description~, by_peer~) =>
      println("toy-ssh client: disconnect code=\{code} \"\{description}\" by_peer=\{by_peer}")
  })
  @sys.exit(exit_code)
}
