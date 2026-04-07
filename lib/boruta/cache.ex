defmodule Boruta.Cache do
  @moduledoc """
  Boruta Ecto adapter uses [Nebulex](https://github.com/cabol/nebulex) in order to cache entities.

  Uses `Nebulex.Adapters.Replicated` (from `nebulex_distributed`) for distributed
  in-memory caching, compatible with Nebulex >= 3.0.
  """

  use Nebulex.Cache,
    otp_app: :boruta,
    adapter: Nebulex.Adapters.Replicated


end
