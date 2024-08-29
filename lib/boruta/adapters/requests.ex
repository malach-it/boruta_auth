defmodule Boruta.RequestsAdapter do
  @moduledoc """
  Encapsulate injected `Boruta.Oauth.Requests` adapter in context configuration
  """
  @behaviour Boruta.Oauth.Requests

  import Boruta.Config, only: [requests: 0]

  def get_request(request_id), do: requests().get_request(request_id)
  def store_request(request, client), do: requests().store_request(request, client)
end
