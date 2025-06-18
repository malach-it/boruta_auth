# Since configuration is shared in umbrella projects, this file
# should only configure the :boruta application itself
# and only for organization purposes. All other config goes to
# the umbrella root.
import Config

config :boruta,
  ecto_repos: [Boruta.Repo]

config :boruta, Boruta.Cache,
  primary: [
    # 1 day
    gc_interval: 86_400_000,
    backend: :shards,
    partitions: 2
  ]

config :phoenix, :json_library, Jason

config :boruta, Boruta.Oauth,
  repo: Boruta.Repo,
  universal_did_auth: %{
    type: "bearer",
    token: System.get_env("DID_SERVICES_API_KEY")
  }

import_config "#{config_env()}.exs"
