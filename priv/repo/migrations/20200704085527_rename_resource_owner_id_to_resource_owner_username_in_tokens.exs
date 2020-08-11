defmodule Boruta.Repo.Migrations.RenameResourceOwnerIdToResourceOwnerSubInTokens do
  use Ecto.Migration

  def change do
    rename table(:tokens), :resource_owner_id, to: :sub
  end
end
