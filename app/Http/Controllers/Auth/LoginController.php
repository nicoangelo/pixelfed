<?php

namespace App\Http\Controllers\Auth;

use App\AccountLog;
use App\Http\Controllers\Controller;
use App\User;
use Illuminate\Auth\Events\Registered;
use Illuminate\Foundation\Auth\AuthenticatesUsers;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;

class LoginController extends Controller
{
    /*
    |--------------------------------------------------------------------------
    | Login Controller
    |--------------------------------------------------------------------------
    |
    | This controller handles authenticating users for the application and
    | redirecting them to your home screen. The controller uses a trait
    | to conveniently provide its functionality to your applications.
    |
     */

    use AuthenticatesUsers;

    /**
     * Where to redirect users after login.
     *
     * @var string
     */
    protected $redirectTo = '/';

    /**
     * Create a new controller instance.
     *
     * @return void
     */
    public function __construct()
    {
        $this->middleware('guest')->except('logout');
    }

    /**
     * Validate the user login request.
     *
     * @param \Illuminate\Http\Request $request
     *
     * @return void
     */
    public function validateLogin($request)
    {
        $rules = [
            $this->username() => 'required|email',
            'password' => 'required|string|min:6',
        ];

        $this->validate($request, $rules);
    }

    /**
     * The user has been authenticated.
     *
     * @param \Illuminate\Http\Request $request
     * @param mixed                    $user
     *
     * @return mixed
     */
    protected function authenticated($request, $user)
    {
        if (!isset($user) || $user->status == 'deleted') {
            return;
        }

        $log = new AccountLog();
        $log->user_id = $user->id;
        $log->item_id = $user->id;
        $log->item_type = 'App\User';
        $log->action = 'auth.login';
        $log->message = 'Account Login';
        $log->link = null;
        $log->ip_address = $request->ip();
        $log->user_agent = $request->userAgent();
        $log->save();
    }

    protected function attemptLogin(Request $request)
    {
        $broker = new \Zefy\LaravelSSO\LaravelSSOBroker;

        $credentials = $this->credentials($request);
        if (Auth::attempt($credentials)) {
            return true;
        } else {
            // try to login via SSO broker
            $broker_login = $broker->login($credentials[$this->username()], $credentials['password']);
            
            if ($broker_login && !User::where('email', $credentials[$this->username()])->exists()) {
                $user_info = $broker->getUserInfo();
                $broker_user = User::create([
                    'name' => $user_info['data']['name'],
                    'username' => str_replace(' ', '_', $user_info['data']['name']),
                    'email' => $user_info['data']['email'],
                    'password' => Hash::make(str_random(20)),
                ]);
                event(new Registered($broker_user));
            }

            return $broker_login;
        }
    }

    public function logout(Request $request)
    {
        $broker = new \Zefy\LaravelSSO\LaravelSSOBroker;

        $broker->logout();
        $this->guard()->logout();
        $request->session()->invalidate();

        return redirect('/');
    }
}
