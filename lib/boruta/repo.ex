defmodule Boruta.Repo do
  @moduledoc false
  use Ecto.Repo,
    otp_app: :boruta_ssi,
    adapter: Ecto.Adapters.Postgres
end
