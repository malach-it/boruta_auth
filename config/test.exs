import Config

config :logger, level: :error

config :boruta_ssi, Boruta.Repo,
  username: System.get_env("POSTGRES_USER") || "postgres",
  password: System.get_env("POSTGRES_PASSWORD") || "postgres",
  database: System.get_env("POSTGRES_DATABASE") || "boruta_test",
  hostname: System.get_env("POSTGRES_HOST") || "localhost",
  pool: Ecto.Adapters.SQL.Sandbox

config :boruta_ssi, Boruta.Oauth,
  contexts: [
    resource_owners: Boruta.Support.ResourceOwners
  ],
  did_resolver_base_url: "https://universalresolver.boruta.patatoid.fr/1.0"
