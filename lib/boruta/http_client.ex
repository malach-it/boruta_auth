defmodule Boruta.HttpClient do
  @moduledoc false

  alias Boruta.Config

  @receive_timeout 15_000

  @spec get(
          url :: String.t(),
          trusted_authorities :: String.t(),
          trusted_hosts :: list(String.t())
        ) ::
          {:ok, Finch.Response.t()} | {:error, term()}
  def get(url, trusted_authorities \\ "", trusted_hosts \\ []) do
    trusted_hosts = add_issuer_host(trusted_hosts)

    get_with_trust(url, trusted_authorities, trusted_hosts)
  end

  defp get_with_trust(_url, "", []),
    do: {:error, "Client must configure trusted hosts or authorities for outbound requests."}

  defp get_with_trust(url, trusted_authorities, trusted_hosts) do
    with {:ok, trusted_hosts} <- validate_trusted_hosts(url, trusted_hosts),
         {:ok, trusted_authorities} <- validate_trusted_authorities(trusted_authorities) do
      trusted_get(url, trusted_hosts, trusted_authorities)
    end
  end

  defp add_issuer_host(trusted_hosts) when is_list(trusted_hosts) do
    case URI.parse(Config.issuer()) do
      %URI{host: host} when is_binary(host) -> [host | trusted_hosts]
      _issuer -> trusted_hosts
    end
  rescue
    _error -> trusted_hosts
  end

  defp add_issuer_host(trusted_hosts), do: trusted_hosts

  defp validate_trusted_hosts(_url, []),
    do: {:ok, []}

  defp validate_trusted_hosts(url, trusted_hosts) when is_list(trusted_hosts) do
    with {:ok, host} <- host_from_url(url),
         {:ok, trusted_hosts} <- normalize_hosts(trusted_hosts),
         true <- Enum.member?(trusted_hosts, host) do
      {:ok, [host]}
    else
      false -> {:error, "Host is not trusted for outbound requests."}
      {:error, reason} -> {:error, reason}
    end
  end

  defp validate_trusted_hosts(_url, _trusted_hosts) do
    {:error, "Invalid trusted hosts configuration."}
  end

  defp host_from_url(url) do
    case Finch.Request.parse_url(url) do
      {scheme, host, _port, _path, _query} when scheme in [:http, :https] ->
        case normalize_host(host) do
          {:ok, normalized_host} -> {:ok, normalized_host}
          :error -> {:error, "Could not parse outbound request host."}
        end

      _ ->
        {:error, "Could not parse outbound request host."}
    end
  rescue
    _error -> {:error, "Could not parse outbound request host."}
  end

  defp normalize_hosts(trusted_hosts) do
    Enum.reduce_while(trusted_hosts, {:ok, []}, fn trusted_host, {:ok, normalized_hosts} ->
      case normalize_host(trusted_host) do
        {:ok, normalized_host} ->
          {:cont, {:ok, [normalized_host | normalized_hosts]}}

        :error ->
          {:halt, {:error, "Invalid trusted hosts configuration."}}
      end
    end)
  end

  defp normalize_host(host) when is_binary(host) do
    case host |> String.trim() |> String.trim_trailing(".") |> String.downcase() do
      "" -> :error
      normalized_host -> {:ok, normalized_host}
    end
  end

  defp normalize_host(_host), do: :error

  defp validate_trusted_authorities(trusted_authorities) do
    case String.trim(trusted_authorities) do
      "" ->
        {:ok, []}

      authorities ->
        decode_trusted_authorities(authorities)
    end
  end

  defp decode_trusted_authorities(authorities) do
    authorities
    |> :public_key.pem_decode()
    |> Enum.filter(&match?({:Certificate, _, :not_encrypted}, &1))
    |> Enum.map(fn {:Certificate, der, :not_encrypted} -> der end)
    |> case do
      [] -> {:error, "Trusted authorities must contain PEM certificates."}
      cacerts -> {:ok, cacerts}
    end
  end

  @dialyzer {:no_opaque, trusted_get: 3}
  defp trusted_get(url, trusted_hosts, trusted_authorities) do
    with {:ok, url, cacerts} <- get_cacerts(url, trusted_hosts, trusted_authorities),
         {:https, host, port, path, _query} <- Finch.Request.parse_url(url) do
      with {:ok, conn} <-
             Mint.HTTP.connect(:https, host, port,
               transport_opts: [cacerts: cacerts],
               protocols: [:http1]
             ),
           {:ok, conn, request_ref} <-
             Mint.HTTP.request(conn, "GET", path, [{"connection", "close"}], nil) do
        receive_response(conn, request_ref, %{status: nil, headers: [], body: []})
      else
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
    else
      {:http, _host, _port, _path, _query} ->
        {:error, "Certificate pinning requires HTTPS."}

      {:error, error} ->
        {:error, error}
    end
  end

  def get_cacerts(url, trusted_hosts, trusted_authorities) when trusted_hosts != [] do
    with {:ok, host} <- host_from_url(url),
         true <- Enum.member?(trusted_hosts, host) do
      case trusted_authorities do
        [] ->
          {:ok, url, :public_key.cacerts_get()}

        trusted_authorities ->
          {:ok, url, trusted_authorities}
      end
    else
      false -> {:error, "Request URL host is not trusted."}
      {:error, reason} -> {:error, reason}
    end
  end

  def get_cacerts(url, _trusted_hosts, trusted_authorities) do
    {:ok, url, trusted_authorities}
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
