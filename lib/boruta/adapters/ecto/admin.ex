defmodule Boruta.Ecto.Admin do
  @moduledoc """
  Administration of Boruta resources.
  """

  defdelegate list_clients, to: Boruta.Ecto.Admin.Clients
  defdelegate get_client!(id), to: Boruta.Ecto.Admin.Clients
  defdelegate create_client(attrs), to: Boruta.Ecto.Admin.Clients
  defdelegate update_client(client, attrs), to: Boruta.Ecto.Admin.Clients
  defdelegate regenerate_client_secret(client), to: Boruta.Ecto.Admin.Clients
  defdelegate regenerate_client_secret(client, secret), to: Boruta.Ecto.Admin.Clients
  defdelegate delete_client(client), to: Boruta.Ecto.Admin.Clients

  defdelegate list_scopes, to: Boruta.Ecto.Admin.Scopes
  defdelegate get_scope!(id), to: Boruta.Ecto.Admin.Scopes
  defdelegate get_scopes_by_ids(ids), to: Boruta.Ecto.Admin.Scopes
  defdelegate get_scopes_by_names(names), to: Boruta.Ecto.Admin.Scopes
  defdelegate create_scope(attrs), to: Boruta.Ecto.Admin.Scopes
  defdelegate update_scope(scope, attrs), to: Boruta.Ecto.Admin.Scopes
  defdelegate delete_scope(scope), to: Boruta.Ecto.Admin.Scopes

  defdelegate list_active_tokens(), to: Boruta.Ecto.Admin.Tokens
  defdelegate list_active_tokens(queryable), to: Boruta.Ecto.Admin.Tokens
  defdelegate delete_inactive_tokens(), to: Boruta.Ecto.Admin.Tokens
  defdelegate delete_inactive_tokens(until), to: Boruta.Ecto.Admin.Tokens
end
