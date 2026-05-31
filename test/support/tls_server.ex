defmodule Boruta.Support.TLSServer do
  @moduledoc false

  defmodule ResponsePlug do
    @moduledoc false

    import Plug.Conn

    def init(opts), do: opts

    def call(conn, opts) do
      conn
      |> put_resp_content_type(Keyword.get(opts, :content_type, "text/plain"))
      |> send_resp(Keyword.get(opts, :status, 200), Keyword.fetch!(opts, :body))
    end
  end

  def start(body, opts \\ []) do
    tmp_dir = Path.join(System.tmp_dir!(), "boruta_tls_#{System.unique_integer([:positive])}")
    File.mkdir_p!(tmp_dir)

    server_certificates = generate_certificates!(tmp_dir, "server")
    wrong_certificates = generate_certificates!(tmp_dir, "wrong")

    with {:ok, server} <- start_https_server(server_certificates, body, opts) do
      {:ok,
       Map.merge(server, %{
         tmp_dir: tmp_dir,
         trusted_authorities: File.read!(server_certificates.ca_certfile),
         wrong_trusted_authorities: File.read!(wrong_certificates.ca_certfile)
       })}
    end
  end

  def stop(%{ref: ref, tmp_dir: tmp_dir}) do
    Plug.Cowboy.shutdown(ref)
    File.rm_rf(tmp_dir)
  end

  defp generate_certificates!(tmp_dir, prefix) do
    ca_keyfile = Path.join(tmp_dir, "#{prefix}_ca.key.pem")
    ca_certfile = Path.join(tmp_dir, "#{prefix}_ca.cert.pem")
    server_keyfile = Path.join(tmp_dir, "#{prefix}_server.key.pem")
    server_csrfile = Path.join(tmp_dir, "#{prefix}_server.csr.pem")
    server_certfile = Path.join(tmp_dir, "#{prefix}_server.cert.pem")
    server_extfile = Path.join(tmp_dir, "#{prefix}_server.ext")

    openssl!([
      "req",
      "-x509",
      "-newkey",
      "rsa:2048",
      "-nodes",
      "-days",
      "1",
      "-subj",
      "/CN=Boruta Test #{prefix} CA",
      "-keyout",
      ca_keyfile,
      "-out",
      ca_certfile
    ])

    openssl!([
      "req",
      "-newkey",
      "rsa:2048",
      "-nodes",
      "-subj",
      "/CN=localhost",
      "-keyout",
      server_keyfile,
      "-out",
      server_csrfile
    ])

    File.write!(server_extfile, """
    basicConstraints=CA:FALSE
    keyUsage=digitalSignature,keyEncipherment
    extendedKeyUsage=serverAuth
    subjectAltName=DNS:localhost,IP:127.0.0.1
    """)

    openssl!([
      "x509",
      "-req",
      "-days",
      "1",
      "-in",
      server_csrfile,
      "-CA",
      ca_certfile,
      "-CAkey",
      ca_keyfile,
      "-CAcreateserial",
      "-out",
      server_certfile,
      "-extfile",
      server_extfile
    ])

    %{
      ca_certfile: ca_certfile,
      server_certfile: server_certfile,
      server_keyfile: server_keyfile
    }
  end

  defp openssl!(args) do
    case System.cmd("openssl", args, stderr_to_stdout: true) do
      {_output, 0} -> :ok
      {output, status} -> raise "openssl failed with status #{status}: #{output}"
    end
  end

  defp start_https_server(%{server_certfile: certfile, server_keyfile: keyfile}, body, opts) do
    ref = :"boruta_tls_#{System.unique_integer([:positive])}"
    port = free_tcp_port()

    with {:ok, _pid} <-
           Plug.Cowboy.https(ResponsePlug, Keyword.merge(opts, body: body),
             ref: ref,
             port: port,
             certfile: certfile,
             keyfile: keyfile
           ) do
      {:ok, %{ref: ref, url: "https://localhost:#{port}"}}
    end
  end

  defp free_tcp_port do
    {:ok, socket} = :gen_tcp.listen(0, [:binary, active: false, reuseaddr: true])
    {:ok, port} = :inet.port(socket)
    :gen_tcp.close(socket)
    port
  end
end
