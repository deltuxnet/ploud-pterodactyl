1) Paste pterodactyl files in your Pterodactyl directory

2) Add to routes/api-application.php in the user controller routes:
    Route::post('/{user:id}/api-keys', [Application\Users\ApiKeyController::class, 'store']);