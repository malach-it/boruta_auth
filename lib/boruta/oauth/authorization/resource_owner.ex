defmodule Boruta.Oauth.Authorization.ResourceOwner do
  @moduledoc """
  Check against given params and return the corresponding resource owner
  """

  import Boruta.Config, only: [resource_owners: 0]

  alias Boruta.Oauth.Error
  alias Boruta.Oauth.ResourceOwner

  @doc """
  Authorize the resource owner corresponding to the given params.

  ## Examples
      iex> authorize(id: "id")
      {:ok, %Boruta.Oauth.ResourceOwner{...}}
  """
  @spec authorize(
    [email: String.t(), password: String.t()] |
    [resource_owner: ResourceOwner.t()]
  ) ::
    {:error,
     %Error{
       :error => :invalid_resource_owner,
       :error_description => String.t(),
       :format => nil,
       :redirect_uri => nil,
       :status => :unauthorized
     }}
    | {:ok, user :: ResourceOwner.t()}
  def authorize(username: username, password: password) do
    with {:ok, resource_owner} <- resource_owners().get_by(username: username),
      :ok <- resource_owners().check_password(resource_owner, password) do
      {:ok, resource_owner}
    else
      {:error, reason} ->
        {:error, %Error{
          status: :unauthorized,
          error: :invalid_resource_owner,
          error_description: reason
        }}
    end
  end
  def authorize(resource_owner: %ResourceOwner{sub: sub} = resource_owner) when not is_nil(sub) do
    {:ok, resource_owner}
  end
  def authorize(_) do
    {:error, %Error{
      status: :unauthorized,
      error: :invalid_resource_owner,
      error_description: "Resource owner is invalid."
    }}
  end
end
