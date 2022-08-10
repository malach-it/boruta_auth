defmodule Boruta.Repo.Migrations.AddRefreshTokenRevokedAtToTokens do
  use Ecto.Migration

  def change do
    alter table(:oauth_tokens) do
      add :refresh_token_revoked_at, :utc_datetime_usec
    end
  end
end
