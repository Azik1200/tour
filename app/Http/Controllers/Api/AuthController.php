<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Models\ApiToken;
use App\Models\User;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;

class AuthController extends Controller
{
    /**
     * Register a new user account.
     */
    public function register(Request $request): JsonResponse
    {
        $validated = $request->validate([
            'first_name' => ['required', 'string', 'max:255'],
            'last_name' => ['required', 'string', 'max:255'],
            'email' => ['required', 'string', 'email', 'max:255', 'unique:users,email'],
            'mobile_number' => ['required', 'string', 'max:30', 'unique:users,mobile_number'],
            'password' => ['required', 'string', 'min:8'],
        ]);

        $user = new User([
            'first_name' => $validated['first_name'],
            'last_name' => $validated['last_name'],
            'email' => $validated['email'],
            'mobile_number' => $validated['mobile_number'],
            'password' => $validated['password'],
        ]);
        $user->name = trim($validated['first_name'].' '.$validated['last_name']);
        $user->save();

        $token = $this->createToken($user, 'registration');

        return response()->json([
            'user' => $user->only([
                'id',
                'first_name',
                'last_name',
                'email',
                'mobile_number',
                'created_at',
                'updated_at',
            ]),
            'token' => $token,
        ], 201);
    }

    /**
     * Attempt to authenticate a user.
     */
    public function login(Request $request): JsonResponse
    {
        $validated = $request->validate([
            'username' => ['required', 'string'],
            'password' => ['required', 'string'],
        ]);

        $user = User::query()
            ->where('email', $validated['username'])
            ->orWhere('mobile_number', $validated['username'])
            ->first();

        if (! $user || ! Hash::check($validated['password'], $user->password)) {
            return response()->json([
                'message' => __('auth.failed'),
            ], 422);
        }

        $token = $this->createToken($user, 'login');

        return response()->json([
            'user' => $user->only([
                'id',
                'first_name',
                'last_name',
                'email',
                'mobile_number',
                'created_at',
                'updated_at',
            ]),
            'token' => $token,
        ]);
    }

    /**
     * Invalidate the current API token.
     */
    public function logout(Request $request): JsonResponse
    {
        /** @var \App\Models\User $user */
        $user = $request->user();
        /** @var \App\Models\ApiToken|null $token */
        $token = $request->attributes->get('apiToken');

        if ($token instanceof ApiToken) {
            $token->delete();
        }

        return response()->json([
            'message' => 'Logged out successfully.',
        ]);
    }

    /**
     * Retrieve the authenticated user's profile.
     */
    public function me(Request $request): JsonResponse
    {
        /** @var \App\Models\User|null $user */
        $user = $request->user();

        if (! $user) {
            return response()->json([
                'message' => 'Unauthenticated.',
            ], 401);
        }

        return response()->json([
            'user' => $user->only([
                'id',
                'first_name',
                'last_name',
                'email',
                'mobile_number',
                'created_at',
                'updated_at',
            ]),
        ]);
    }

    /**
     * Create a new API token for the user.
     */
    protected function createToken(User $user, string $name): string
    {
        $user->apiTokens()->where('expires_at', '<', now())->delete();

        $plainTextToken = Str::random(60);

        $user->apiTokens()->create([
            'name' => $name,
            'token' => hash('sha256', $plainTextToken),
            'last_used_at' => now(),
            'expires_at' => now()->addDays(30),
        ]);

        return $plainTextToken;
    }
}
