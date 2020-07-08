defmodule Boruta.Repo.Migrations.RenameResourceOwnerIdToResourceOwnerUsernameInTokens do
  use Ecto.Migration

  def change do
    rename table(:tokens), :resource_owner_id, to: :resource_owner_username
  end
end
