defmodule Boruta.Did do
  @moduledoc """
    Utilities to manipulate dids using an universal resolver or registrar.
  """

  import Boruta.Config, only: [universalresolver_base_url: 0]

  @spec resolve(did :: String.t()) :: {:ok, did_document :: map()} | {:error, reason :: String.t()}
  def resolve(did) do
    resolver_url = "#{universalresolver_base_url()}/1.0/identifiers/#{did}"

    case Finch.build(:get, resolver_url) |> Finch.request(OpenIDHttpClient) do
      {:ok, %Finch.Response{body: body, status: 200}} ->
        Jason.decode(body)
      {:ok, %Finch.Response{body: body}} ->
          {:error, body}
      {:error, error} ->
          {:error, inspect(error)}
    end
  end
end
