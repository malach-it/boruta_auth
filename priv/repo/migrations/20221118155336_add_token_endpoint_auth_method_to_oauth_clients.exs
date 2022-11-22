defmodule Boruta.Repo.Migrations.AddTokenEndpointAuthMethodToOauthClients do
  use Ecto.Migration

  def change do
    alter table(:oauth_clients) do
      add :token_endpoint_auth_methods, {:array, :string}, null: false,
        default: ["client_secret_basic", "client_secret_post"]
    end
  end
end
