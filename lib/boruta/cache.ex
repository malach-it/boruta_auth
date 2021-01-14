defmodule Boruta.Cache do
  @moduledoc false

  use Nebulex.Cache,
    otp_app: :boruta,
    adapter: Nebulex.Adapters.Replicated
end
