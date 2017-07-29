defmodule DiscOAuth2 do
  @api_base "https://discordapp.com/api/"
  @oauth_base "https://discordapp.com/api/oauth2/"

  @doc """
  Gets a Bearer token from Discord given the following args:
    `code` OAuth2 code granted by the redirect
    `redirect_uri` A redirect URI that has been authorized on the app page
    `client_id` The client ID of the application
    `client_secret` The client secret of the application
    Optional:
      `headers` Optionally provide your own headers to the request
      `url_args` Provide additional arguments to the URL

  Returns Map.t

  ## Examples

    iex> DiscOAuth2.get_token(
      "w6C9RrfNtzIdtDhPYvBgRktE9ryvzR",
      "http://my-app.com/authorize",
      "80351110224678912",
      "ldPPl75_mhTUnlwYcO-j-_RYJdlH32tG"
    )
    {:ok, %{
      "id" => "80351110224678912",
      "username" => "Nelly",
      "discriminator" => "1337",
      "avatar" => "8342729096ea3675442027381ff50dfe",
      "verified" => true,
      "email" => "nelly@discordapp.com"
    }}

  """
  def get_token(code, redirect_uri, client_id, client_secret, headers \\ %{}, body_args \\ %{}) do
    body = %{
             code: code,
             grant_type: "authorization_code",
             redirect_uri: redirect_uri,
            }
    args = URI.encode_query(Map.merge(body, body_args))
    auth = Base.encode64("#{client_id}:#{client_secret}")
    authheaders = %{
      "Authorization" => "Basic #{auth}",
      "Content-Type" => "application/x-www-form-urlencoded"
    }
    full_url = "#{@oauth_base}token"
    case HTTPoison.post(full_url, args, Map.merge(authheaders, headers)) do
      {:ok, response} -> Poison.decode(response.body)
      error -> error
    end
  end

  def get_token!(code, redirect_uri, client_id, client_secret, headers \\ %{}, body_args \\ %{}) do
    body = %{
             code: code,
             grant_type: "authorization_code",
             redirect_uri: redirect_uri,
            }
    args = URI.encode_query(Map.merge(body, body_args))
    auth = Base.encode64("#{client_id}:#{client_secret}")
    authheaders = %{
      "Authorization" => "Basic #{auth}",
      "Content-Type" => "application/x-www-form-urlencoded"
    }
    ("#{@oauth_base}token"
    |> HTTPoison.post!(args, Map.merge(authheaders, headers))).body
    |> Poison.decode!
  end

  def get_userdata!(token, user_id \\ "@me") do
    headers = %{
      Authorization: "Bearer #{token}"
    }
    ("#{@api_base}users/#{user_id}"
    |> HTTPoison.get!(headers)).body
    |> Poison.decode!
  end
  
  def get_me!(code, redirect_uri, client_id, client_secret) do
    get_token!(code, redirect_uri, client_id, client_secret)
    |> Map.get("access_token")
    |> get_userdata!
  end
end
