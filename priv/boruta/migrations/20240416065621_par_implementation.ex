defmodule Boruta.Migrations.ParImplementation do
  @moduledoc false

  defmacro __using__(_args) do
    quote do
      def change do
        # 20240408194443_create_authorization_requests.exs
        create table(:authorization_requests, primary_key: false) do
          add :id, :uuid, primary_key: true
          add :client_id, :string
          add :client_authentication, :jsonb
          add :response_type, :string
          add :redirect_uri, :string
          add :scope, :string
          add :state, :string
          add :code_challenge, :string
          add :code_challenge_method, :string
          add :expires_at, :integer

          timestamps()
        end

        alter table(:oauth_clients) do
          add :authorization_request_ttl, :integer, default: 60
        end
      end
    end
  end
end

