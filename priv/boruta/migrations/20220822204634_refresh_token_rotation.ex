defmodule Boruta.Migrations.RefreshTokenRotation do
  @moduledoc false

  defmacro __using__(_args) do
    quote do
      def change do
        # 20220810192111_add_refresh_token_revoked_at_to_tokens.exs
        alter table(:oauth_tokens) do
          add :refresh_token_revoked_at, :utc_datetime_usec
        end
      end
    end
  end
end
