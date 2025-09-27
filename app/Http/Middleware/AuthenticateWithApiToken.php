<?php

namespace App\Http\Middleware;

use App\Models\ApiToken;
use Closure;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class AuthenticateWithApiToken
{
    /**
     * Handle an incoming request.
     *
     * @param  \Closure(\Illuminate\Http\Request): (\Symfony\Component\HttpFoundation\Response)  $next
     */
    public function handle(Request $request, Closure $next): Response
    {
        $plainToken = $request->bearerToken();

        if (! $plainToken) {
            return $this->unauthorizedResponse();
        }

        $hashedToken = hash('sha256', $plainToken);

        $apiToken = ApiToken::query()
            ->with('user')
            ->where('token', $hashedToken)
            ->first();

        if (! $apiToken || ($apiToken->expires_at && $apiToken->expires_at->isPast())) {
            return $this->unauthorizedResponse();
        }

        $apiToken->forceFill(['last_used_at' => now()])->save();

        /** @var Authenticatable|null $user */
        $user = $apiToken->user;

        if (! $user) {
            return $this->unauthorizedResponse();
        }

        $request->setUserResolver(static fn (): ?Authenticatable => $user);
        $request->attributes->set('apiToken', $apiToken);

        return $next($request);
    }

    protected function unauthorizedResponse(): JsonResponse
    {
        return response()->json([
            'message' => 'Unauthenticated.',
        ], 401);
    }
}
