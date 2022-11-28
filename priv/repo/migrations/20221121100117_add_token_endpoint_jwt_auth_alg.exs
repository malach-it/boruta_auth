defmodule Boruta.Repo.Migrations.AddTokenEndpointJwtAuthAlg do
  use Ecto.Migration

  def change do
    alter table(:oauth_clients) do
      add :token_endpoint_jwt_auth_alg, :string, default: "HS256", null: false
    end
  end
end
