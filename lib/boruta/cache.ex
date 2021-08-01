defmodule Boruta.Cache do
  @moduledoc """
  Boruta Ecto adapter uses [Nebulex](https://github.com/cabol/nebulex) in order to cache entities
  """

  use Nebulex.Cache,
    otp_app: :boruta,
    adapter: Nebulex.Adapters.Replicated
end
