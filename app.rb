require 'colorize' # Just to add fancy colour in the server log
require 'rack-flash'
require 'sinatra'
require 'sinatra/json'
require 'sinatra/activerecord'
require 'warden'
require_relative 'model'

set :database_file, 'config/database.yml'

use Rack::Flash

use Rack::Session::Cookie, secret: SecureRandom.uuid

use Warden::Manager do |config|
  # Tell Warden how to save our User info into a session.  Sessions can only take strings,
  # not Ruby code, we'll store the User's `id`
  config.serialize_into_session(&:id)

  # Tell Warden how to take what we've stored in the session and get a User from that information.
  config.serialize_from_session { |id| User.find(id) }

  # 'strategies' is an array of named methods with which to attempt authentication. We have to define this later.
  # The action is a route to send the user to when warden.authenticate! returns a false answer. We'll show this route below.
  config.scope_defaults :default, strategies: [:password], action: '/unauthenticated'

  # When a user tries to log in and cannot, this specifies the app to send the user to.
  # Here I'm using classic sinatra application style, hence 'Sinatra::Application'. If you're
  # using the modular sinatra style, then you'd use `self` or the class name of your app
  config.failure_app = Sinatra::Application
end

Warden::Strategies.add(:password) do
  def valid?
    puts '(Warden::Strategies) valid?'.colorize(:blue)
    params['username'] && params['password']
  end

  def authenticate!
    puts '(Warden::Strategies) authenticate!'.colorize(:blue)
    user = User.find_by(username: params['username'])

    if user&.authenticate(params['password'])
      puts '(Warden::Strategies) user present and authenticate returns true'.colorize(:green)
      success!(user)
    else
      puts '(Warden::Strategies) could not authenticate'.colorize(:red)
      fail!('Could not log in')
    end
  end
end

# Without this, failed calls to authenticate! would redirect based on the method of the request
# which means we'd have to implement GET /unauthenticated, POST /unauthenticated, etc.
# Doing this, we'll just deal with one route of failed authentication -> POST /unauthenticated
Warden::Manager.before_failure do |env, _opts|
  env['REQUEST_METHOD'] = 'POST'
end

#
# HELPERS
#

helpers do
  def authenticated?
    env['warden'].user.present?
  end
end

before do
  @current_user = env['warden'].user
end

#
# ROUTES
#

get '/' do
  erb :index
end

get '/login' do
  erb :login
end

# The login form submits a request to this 'POST login' route
# Warden tries to authenticate based on the params username and password
# If authentication is successful, user is redirected. If authentication
# fails, it's handled in the strategy `authenticate!` method.
post '/login' do
  env['warden'].authenticate!
  flash[:success] = 'Logged in!'

  redirect_to = session[:return_to] || '/protected'
  puts "logged in, redirect to #{redirect_to}".colorize(:green)

  redirect redirect_to
end

get '/logout' do
  env['warden'].logout

  flash[:success] = 'Successfully logged out'
  redirect '/'
end

post '/unauthenticated' do
  puts 'POST /unauthenticated'.colorize(:red)
  session[:return_to] = env['warden.options'][:attempted_path]

  flash[:error] = env['warden'].message || 'You must log in'
  redirect '/login'
end

get '/protected' do
  env['warden'].authenticate!
  erb :protected
end

get '/forgot_password' do
  erb :forgot_password
end

post '/forgot_password' do
  user = User.find_by(email: params[:email])
  if user
    user.generate_password_reset_token!
    flash[:notice] = 'An email has been sent with instructions on how to reset your password.'
  else
    flash[:error] = 'No user was found with that email address.'
  end
  redirect '/forgot_password'
end

get '/reset_password/:token' do
  user = User.find_by(password_reset_token: params[:token])
  if user && @user.password_reset_sent_at > 2.hours.ago
    erb :reset_password
  else
    flash[:error] = 'The password reset link has expired or is invalid.'
    redirect '/forgot_password'
  end
end

post '/reset_password/:token' do
  user = User.find_by(password_reset_token: params[:token])
  unless user
    flash[:error] = 'Invalid password reset link.'
    redirect '/login'
    return
  end
  if user.password_reset_sent_at < 2.hours.ago
    if user.update(password: params[:password], password_confirmation: params[:password_confirmation])
      user.clear_password_reset_token!
      flash[:notice] = 'Your password has been reset.'
      redirect '/login'
    else
      erb :reset_password
    end
  else
    flash[:error] = 'The password reset link has expired or is invalid.'
    redirect '/forgot_password'
  end
end

not_found do
  redirect '/' # catch redirects to GET '/session'
end
