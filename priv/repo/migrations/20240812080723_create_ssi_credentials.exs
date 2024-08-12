defmodule Boruta.Repo.Migrations.CreateSsiCredentials do
  use Ecto.Migration

  def change do
    create table(:ssi_credentials, primary_key: false) do
      add :id, :uuid, primary_key: true
      add :format, :string, null: false
      add :credential, :text, null: false
      add :access_token, :string, null: false
      add :defered, :boolean, null: false

      timestamps()
    end
  end
end
