# Since configuration is shared in umbrella projects, this file
# should only configure the :boruta application itself
# and only for organization purposes. All other config goes to
# the umbrella root.
use Mix.Config

config :boruta,
  ecto_repos: [Boruta.Repo]

config :boruta, Boruta.Cache,
  primary: [
    gc_interval: 86_400_000, #=> 1 day
    backend: :shards,
    partitions: 2
  ]

config :phoenix, :json_library, Jason

config :boruta, Boruta.Oauth,
  repo: Boruta.Repo

import_config "#{Mix.env()}.exs"
