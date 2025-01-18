import Config

config :boruta_ssi,
  ecto_repos: [Boruta.Repo]

config :boruta_ssi, Boruta.Cache,
  primary: [
    gc_interval: 86_400_000, #=> 1 day
    backend: :shards,
    partitions: 2
  ]

config :phoenix, :json_library, Jason

config :boruta_ssi, Boruta.Oauth,
  repo: Boruta.Repo

import_config "#{config_env()}.exs"
