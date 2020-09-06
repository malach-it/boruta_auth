defmodule Boruta.Repo.Migrations.AddRevokedAtToTokens do
  use Ecto.Migration

  def change do
    alter table(:tokens) do
      add :revoked_at, :utc_datetime_usec
    end
  end
end
