import Config

# Configure your database
config :boruta_ssi, Boruta.Repo,
  username: "postgres",
  password: "postgres",
  database: "boruta_auth",
  hostname: "localhost",
  pool_size: 10

config :boruta_ssi, Boruta.Oauth,
  contexts: [
    resource_owners: Dummy.ResourceOwners
  ]
