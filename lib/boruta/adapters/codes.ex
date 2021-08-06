defmodule Boruta.CodesAdapter do
  @moduledoc """
  Encapsulate injected codes adapter in context configuration.
  """

  @behaviour Boruta.Oauth.Codes

  import Boruta.Config, only: [codes: 0]

  defdelegate get_by(params), to: codes()
  defdelegate create(params), to: codes()
end
