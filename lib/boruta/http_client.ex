defmodule Boruta.HttpClient do
  @moduledoc false

  @receive_timeout 15_000

  @spec get(url :: String.t(), trusted_authorities :: String.t() | nil) ::
          {:ok, Finch.Response.t()} | {:error, term()}
  def get(url, nil), do: Finch.build(:get, url) |> Finch.request(OpenIDHttpClient)

  def get(url, trusted_authorities) when is_binary(trusted_authorities) do
    case parse_trusted_authorities(trusted_authorities) do
      {:ok, cacerts} -> pinned_get(url, cacerts)
      {:error, reason} -> {:error, reason}
    end
  end

  def get(url, _trusted_authorities),
    do: Finch.build(:get, url) |> Finch.request(OpenIDHttpClient)

  defp parse_trusted_authorities(trusted_authorities) do
    trusted_authorities
    |> String.trim()
    |> case do
      "" ->
        {:error, "Client do not trust authorities for outbound requests."}

      authorities ->
        case authorities
             |> :public_key.pem_decode()
             |> Enum.filter(&match?({:Certificate, _, :not_encrypted}, &1))
             |> Enum.map(fn {:Certificate, der, :not_encrypted} -> der end) do
          [] -> {:error, "Trusted authorities must contain PEM certificates."}
          cacerts -> {:ok, cacerts}
        end
    end
  end

  defp pinned_get(url, cacerts) do
    case Finch.Request.parse_url(url) do
      {:https, host, port, path, query} ->
        request_path = if query in [nil, ""], do: path, else: "#{path}?#{query}"

        case (with {:ok, conn} <-
                     Mint.HTTP.connect(:https, host, port,
                       transport_opts: [cacerts: cacerts],
                       protocols: [:http1]
                     ),
                   {:ok, conn, request_ref} <-
                     Mint.HTTP.request(conn, "GET", request_path, [{"connection", "close"}], nil) do
                receive_response(conn, request_ref, %{status: nil, headers: [], body: []})
              end) do
          {:error,
           %Mint.TransportError{
             reason: {:tls_alert, _}
           }} ->
            {:error, "Host certificate is not trusted."}

          {:error, reason} ->
            {:error, reason}

          response ->
            response
        end

      {:http, _host, _port, _path, _query} ->
        {:error, "Certificate pinning requires HTTPS."}
    end
  rescue
    _error -> {:error, "Could not parse trusted authorities."}
  end

  defp receive_response(conn, request_ref, response) do
    receive do
      message ->
        case Mint.HTTP.stream(conn, message) do
          {:ok, conn, responses} ->
            response = collect_responses(responses, request_ref, response)

            if response[:done] do
              Mint.HTTP.close(conn)

              case response[:error] do
                nil ->
                  {:ok,
                   %Finch.Response{
                     status: response.status,
                     headers: response.headers,
                     body: IO.iodata_to_binary(Enum.reverse(response.body))
                   }}

                reason ->
                  {:error, reason}
              end
            else
              receive_response(conn, request_ref, response)
            end

          {:error, conn, reason, _responses} ->
            Mint.HTTP.close(conn)
            {:error, reason}

          :unknown ->
            receive_response(conn, request_ref, response)
        end
    after
      @receive_timeout ->
        Mint.HTTP.close(conn)
        {:error, :timeout}
    end
  end

  defp collect_responses(responses, request_ref, response) do
    Enum.reduce(responses, response, fn
      {:status, ^request_ref, status}, response ->
        %{response | status: status}

      {:headers, ^request_ref, headers}, response ->
        %{response | headers: response.headers ++ headers}

      {:data, ^request_ref, data}, response ->
        %{response | body: [data | response.body]}

      {:done, ^request_ref}, response ->
        Map.put(response, :done, true)

      {:error, ^request_ref, reason}, response ->
        response
        |> Map.put(:done, true)
        |> Map.put(:error, reason)

      _response, response ->
        response
    end)
  end
end
