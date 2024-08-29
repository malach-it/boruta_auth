defmodule Boruta.Migrations.DeferedCredentials do
  @moduledoc false

  defmacro __using__(_args) do
    quote do
      def change do
        # 20240812080723_create_ssi_credentials.exs
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
  end
end

