package usecases_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/AzimBB/go-chat-app-backend/internal/domain/entities"
	app_errors "github.com/AzimBB/go-chat-app-backend/internal/domain/errors"
	usecases "github.com/AzimBB/go-chat-app-backend/internal/usecases/user_auth_service"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type UserAuthMocks struct {
	ctx                context.Context
	mockUserRepo       *usecases.MockUserRepository
	mockJWTService     *usecases.MockJWTService
	mockCache          *usecases.MockCache
	mockMailingService *usecases.MockMailingService
	mockActivation     time.Duration
	mockLogger         *usecases.MockLogger
	mockUserAuth       *usecases.UserAuthServiceImpl
}

func GetNewUserAuthMocks(t *testing.T) *UserAuthMocks {

	ctx := context.Background()
	mockUserRepo := usecases.NewMockUserRepository(t)
	mockJWTService := usecases.NewMockJWTService(t)
	mockCache := usecases.NewMockCache(t)
	mockMailingService := usecases.NewMockMailingService(t)
	mockActivation := time.Minute * 5
	mockLogger := usecases.NewMockLogger(t)

	mockUserAuth := &usecases.UserAuthServiceImpl{
		UserRepository:       mockUserRepo,
		JWTService:           mockJWTService,
		Cache:                mockCache,
		MailingService:       mockMailingService,
		ActivationTimeExpiry: mockActivation,
		Logger:               mockLogger,
	}

	return &UserAuthMocks{
		ctx:                ctx,
		mockUserRepo:       mockUserRepo,
		mockJWTService:     mockJWTService,
		mockCache:          mockCache,
		mockMailingService: mockMailingService,
		mockActivation:     mockActivation,
		mockLogger:         mockLogger,
		mockUserAuth:       mockUserAuth,
	}
}

var mockUser = entities.User{
	Email:        "example@email.com",
	PasswordHash: []byte("hashhashhashhashhashhashhashhashhashhash"),
}

var newRandomLinkString string = "sdfgsdfgdsfg"

func Test_RegisterUser(t *testing.T) {

	RegisterUserTests := []struct {
		name     string
		runMocks func(*UserAuthMocks)
		Error    error
	}{
		{
			name: "Success: User Registrated succesfully ",
			runMocks: func(mocks *UserAuthMocks) {
				mocks.mockUserRepo.EXPECT().CheckEmailExistence(mocks.ctx, mockUser.Email).Return(nil)
				mocks.mockJWTService.EXPECT().GenerateActivationLink(mocks.ctx).Return(mock.Anything, nil)
				mocks.mockCache.EXPECT().SaveUserInCache(mocks.ctx, newRandomLinkString, mockUser, mocks.mockUserAuth.ActivationTimeExpiry).Return(nil)
				mocks.mockMailingService.EXPECT().SendActivationLink(mocks.ctx, mockUser.Email, newRandomLinkString).Return(nil)

			},
			Error: nil,
		},
		{
			name: "FAil : CheckEmailExistence, User already exists",
			runMocks: func(mocks *UserAuthMocks) {
				mocks.mockUserRepo.EXPECT().CheckEmailExistence(mocks.ctx, mockUser.Email).Return(app_errors.ErrUserAlreadyExists)
				mocks.mockLogger.EXPECT().Info(app_errors.ErrUserAlreadyExists.Error(), mock.Anything, mock.Anything).Once()
			},
			Error: app_errors.ErrUserAlreadyExists,
		},
		{
			name: "Fail : CheckEmailExistence, Cache is not fetching",
			runMocks: func(mocks *UserAuthMocks) {
				mocks.mockUserRepo.EXPECT().CheckEmailExistence(mocks.ctx, mockUser.Email).Return(app_errors.ErrInternalServerError)
				mocks.mockLogger.EXPECT().Error(app_errors.ErrInternalServerError, mock.Anything, mock.Anything, mock.Anything).Once()
			},
			Error: app_errors.ErrInternalServerError,
		},
		{
			name: "Fail:  GenerateActivationLink ",
			runMocks: func(mocks *UserAuthMocks) {
				mocks.mockUserRepo.EXPECT().CheckEmailExistence(mocks.ctx, mockUser.Email).Return(nil)
				mocks.mockJWTService.EXPECT().GenerateActivationLink(mocks.ctx).Return(mock.Anything, app_errors.ErrInternalServerError)
				mocks.mockLogger.EXPECT().Error(app_errors.ErrInternalServerError, mock.Anything, mock.Anything, mock.Anything).Once()

			},
			Error: app_errors.ErrInternalServerError,
		},
		{
			name: "Fail:  Internal server error , mailing is down ",
			runMocks: func(mocks *UserAuthMocks) {
				mocks.mockUserRepo.EXPECT().CheckEmailExistence(mocks.ctx, mockUser.Email).Return(nil)
				mocks.mockJWTService.EXPECT().GenerateActivationLink(mocks.ctx).Return(mock.Anything, nil)
				mocks.mockCache.EXPECT().SaveUserInCache(mocks.ctx, newRandomLinkString, mockUser, mocks.mockUserAuth.ActivationTimeExpiry).Return(app_errors.ErrInternalServerError)
				mocks.mockLogger.EXPECT().Error(app_errors.ErrInternalServerError, mock.Anything, mock.Anything, mock.Anything).Once()

			},
			Error: app_errors.ErrInternalServerError,
		},
		{
			name: "Error:  Internal server error , cache is down ",
			runMocks: func(mocks *UserAuthMocks) {
				mocks.mockUserRepo.EXPECT().CheckEmailExistence(mocks.ctx, mockUser.Email).Return(nil)
				mocks.mockJWTService.EXPECT().GenerateActivationLink(mocks.ctx).Return(mock.Anything, nil)
				mocks.mockCache.EXPECT().SaveUserInCache(mocks.ctx, newRandomLinkString, mockUser, mocks.mockUserAuth.ActivationTimeExpiry).Return(app_errors.ErrInternalServerError)
				mocks.mockLogger.EXPECT().Error(mock.Anything, mock.Anything, mock.Anything).Once()
			},
			Error: app_errors.ErrInternalServerError,
		},
	}

	for _, val := range RegisterUserTests {

		mocks := GetNewUserAuthMocks(t)

		val.runMocks(mocks)

		err := mocks.mockUserAuth.Register(mocks.ctx, mockUser)

		if err == nil {
			assert.NoError(t, err)
		} else {
			assert.Error(t, err)
			assert.True(t, errors.Is(err, val.Error), "Expected error: %v, but got : %v", val.Error, err)
		}

	}

}

func Test_ActivateUser(t *testing.T) {

	var randomUndefinedError error = app_errors.ErrInternalServerError
	ActivateUserTests := []struct {
		name     string
		runMocks func(*UserAuthMocks)
		Error    error
	}{
		{
			name: "Success: Activated user , user allowed to login by his credentials",
			runMocks: func(userAuthMocks *UserAuthMocks) {
				userAuthMocks.mockCache.EXPECT().GetUserFromCache(userAuthMocks.ctx, newRandomLinkString).Return(mockUser, nil)
				userAuthMocks.mockUserRepo.EXPECT().Create(userAuthMocks.ctx, &mockUser).Return(nil)
				userAuthMocks.mockCache.EXPECT().RemoveFromCacheByKey(userAuthMocks.ctx, newRandomLinkString).Return(nil)
			},
			Error: nil,
		},
		{
			name: "Fail: Activated time is expired ",
			runMocks: func(userAuthMocks *UserAuthMocks) {
				userAuthMocks.mockCache.EXPECT().GetUserFromCache(userAuthMocks.ctx, newRandomLinkString).Return(mockUser, app_errors.ErrActivationTimeExpired)
				userAuthMocks.mockLogger.EXPECT().Info(app_errors.ErrActivationTimeExpired.Error(), mock.Anything, mock.Anything).Once()
			},
			Error: app_errors.ErrActivationTimeExpired,
		},
		{
			name: "Fail: Internal server error",
			runMocks: func(userAuthMocks *UserAuthMocks) {
				userAuthMocks.mockCache.EXPECT().GetUserFromCache(userAuthMocks.ctx, newRandomLinkString).Return(mockUser, randomUndefinedError)
				userAuthMocks.mockLogger.EXPECT().Error(randomUndefinedError, mock.Anything, mock.Anything, mock.Anything).Once()

			},
			Error: randomUndefinedError,
		},
		{
			name: "Fail: user creation inside the repo is failed",
			runMocks: func(userAuthMocks *UserAuthMocks) {
				userAuthMocks.mockCache.EXPECT().GetUserFromCache(userAuthMocks.ctx, newRandomLinkString).Return(mockUser, nil)
				userAuthMocks.mockUserRepo.EXPECT().Create(userAuthMocks.ctx, &mockUser).Return(randomUndefinedError)
				userAuthMocks.mockLogger.EXPECT().Error(randomUndefinedError, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Once()

			},
			Error: randomUndefinedError,
		},
		{
			name: "Fail: Activated user , user allowed to login by his credentials",
			runMocks: func(userAuthMocks *UserAuthMocks) {
				userAuthMocks.mockCache.EXPECT().GetUserFromCache(userAuthMocks.ctx, newRandomLinkString).Return(mockUser, nil)
				userAuthMocks.mockUserRepo.EXPECT().Create(userAuthMocks.ctx, &mockUser).Return(nil)
				userAuthMocks.mockCache.EXPECT().RemoveFromCacheByKey(userAuthMocks.ctx, newRandomLinkString).Return(randomUndefinedError)
				userAuthMocks.mockLogger.EXPECT().Error(randomUndefinedError, mock.Anything, mock.Anything, mock.Anything)

			},
			Error: randomUndefinedError,
		},
	}

	for _, test := range ActivateUserTests {
		userAuthMocks := GetNewUserAuthMocks(t)

		test.runMocks(userAuthMocks)

		err := userAuthMocks.mockUserAuth.ActivateUser(userAuthMocks.ctx, newRandomLinkString)

		if err == nil {
			assert.NoError(t, err)
		} else {
			assert.Error(t, err)
			assert.True(t, errors.Is(err, test.Error), "Expected: %v  ; but got : %v", test.Error, err)
		}
	}
}

func Test_Login(t *testing.T) {
	var randomUndefinedError error = app_errors.ErrInternalServerError

	LoginTests := []struct {
		name     string
		runMocks func(*UserAuthMocks)
		Error    error
	}{
		{
			name: "Success:  User logged in successfully",
			runMocks: func(userAuthMocks *UserAuthMocks) {
				userAuthMocks.mockUserRepo.EXPECT().CheckPassword(userAuthMocks.ctx, mockUser.Email, string(mockUser.PasswordHash)).Return(nil)
				userAuthMocks.mockUserRepo.EXPECT().GetUserIDByEmail(userAuthMocks.ctx, mock.Anything).Return(mockUser.ID, nil)
				userAuthMocks.mockJWTService.EXPECT().GenerateTokenPair(userAuthMocks.ctx, mock.Anything).Return(mock.Anything, mock.Anything, nil)
				userAuthMocks.mockJWTService.EXPECT().CreateSession(userAuthMocks.ctx, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(entities.Session{}, nil)
				userAuthMocks.mockCache.EXPECT().SaveSession(userAuthMocks.ctx, entities.Session{}).Return(nil)
			},
			Error: nil,
		},
		{
			name: "Fail:  User logged in successfully",
			runMocks: func(userAuthMocks *UserAuthMocks) {
				userAuthMocks.mockUserRepo.EXPECT().CheckPassword(userAuthMocks.ctx, mockUser.Email, string(mockUser.PasswordHash)).Return(app_errors.InvalidCredentials)
				userAuthMocks.mockLogger.EXPECT().Info(app_errors.InvalidCredentials.Error(), mock.Anything, mock.Anything, mock.Anything, mock.Anything)
			},
			Error: app_errors.InvalidCredentials,
		},
		{
			name: "Fail:  check password",
			runMocks: func(userAuthMocks *UserAuthMocks) {
				userAuthMocks.mockUserRepo.EXPECT().CheckPassword(userAuthMocks.ctx, mockUser.Email, string(mockUser.PasswordHash)).Return(randomUndefinedError)
				userAuthMocks.mockLogger.EXPECT().Error(randomUndefinedError, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything)
			},
			Error: randomUndefinedError,
		},
		{
			name: "Fail:  GetUserIDByEmail",
			runMocks: func(userAuthMocks *UserAuthMocks) {
				userAuthMocks.mockUserRepo.EXPECT().CheckPassword(userAuthMocks.ctx, mockUser.Email, string(mockUser.PasswordHash)).Return(nil)
				userAuthMocks.mockUserRepo.EXPECT().GetUserIDByEmail(userAuthMocks.ctx, mock.Anything).Return(mockUser.ID, randomUndefinedError)
				userAuthMocks.mockLogger.EXPECT().Error(randomUndefinedError, mock.Anything, mock.Anything, mock.Anything)
			},
			Error: randomUndefinedError,
		},
		{
			name: "Fail:  GenerateTokenPair",
			runMocks: func(userAuthMocks *UserAuthMocks) {
				userAuthMocks.mockUserRepo.EXPECT().CheckPassword(userAuthMocks.ctx, mockUser.Email, string(mockUser.PasswordHash)).Return(nil)
				userAuthMocks.mockUserRepo.EXPECT().GetUserIDByEmail(userAuthMocks.ctx, mock.Anything).Return(mockUser.ID, nil)
				userAuthMocks.mockJWTService.EXPECT().GenerateTokenPair(userAuthMocks.ctx, mock.Anything).Return(mock.Anything, mock.Anything, randomUndefinedError)
				userAuthMocks.mockLogger.EXPECT().Error(randomUndefinedError, mock.Anything, mock.Anything, mock.Anything)

			},
			Error: randomUndefinedError,
		},
		{
			name: "Fail:  CreateSession",
			runMocks: func(userAuthMocks *UserAuthMocks) {
				userAuthMocks.mockUserRepo.EXPECT().CheckPassword(userAuthMocks.ctx, mockUser.Email, string(mockUser.PasswordHash)).Return(nil)
				userAuthMocks.mockUserRepo.EXPECT().GetUserIDByEmail(userAuthMocks.ctx, mock.Anything).Return(mockUser.ID, nil)
				userAuthMocks.mockJWTService.EXPECT().GenerateTokenPair(userAuthMocks.ctx, mock.Anything).Return(mock.Anything, mock.Anything, nil)
				userAuthMocks.mockJWTService.EXPECT().CreateSession(userAuthMocks.ctx, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(entities.Session{}, randomUndefinedError)
				userAuthMocks.mockLogger.EXPECT().Error(randomUndefinedError, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything)

			},
			Error: randomUndefinedError,
		},
		{
			name: "Fail:  SaveSession",
			runMocks: func(userAuthMocks *UserAuthMocks) {
				userAuthMocks.mockUserRepo.EXPECT().
					CheckPassword(userAuthMocks.ctx, mockUser.Email, string(mockUser.PasswordHash)).Return(nil)
				userAuthMocks.mockUserRepo.EXPECT().
					GetUserIDByEmail(userAuthMocks.ctx, mock.Anything).Return(mockUser.ID, nil)
				userAuthMocks.mockJWTService.EXPECT().
					GenerateTokenPair(userAuthMocks.ctx, mock.Anything).Return(mock.Anything, mock.Anything, nil)
				userAuthMocks.mockJWTService.EXPECT().
					CreateSession(userAuthMocks.ctx, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(entities.Session{}, nil)
				userAuthMocks.mockCache.EXPECT().
					SaveSession(userAuthMocks.ctx, entities.Session{}).Return(randomUndefinedError)
				userAuthMocks.mockLogger.EXPECT().Error(randomUndefinedError, mock.Anything, mock.Anything, mock.Anything)

			},
			Error: randomUndefinedError,
		},
	}

	for _, test := range LoginTests {
		userAuthMocks := GetNewUserAuthMocks(t)

		test.runMocks(userAuthMocks)

		_, _, err := userAuthMocks.mockUserAuth.Login(userAuthMocks.ctx, mockUser.Email, string(mockUser.PasswordHash), mock.Anything, mock.Anything)

		if err == nil {
			assert.NoError(t, err)
		} else {
			assert.Error(t, err)
			assert.True(t, errors.Is(err, test.Error), "Expected: %v  ; but got : %v", test.Error, err)
		}
	}

}

// Test_Refresh 9 FAILS , 1 SUCCESS
func Test_Refresh(t *testing.T) {

	var randomUndefinedError error = app_errors.ErrInternalServerError
	var newAccessToken = "newAccesToken"
	mockSession := entities.Session{
		ID:           "mockSessionID",
		UserID:       "userID",
		IsAdmin:      false,
		RefreshToken: mock.Anything,

		ExpiresAt: time.Now().Add(time.Hour),

		UserAgent: mock.Anything,
		ClientIP:  mock.Anything,
	}
	mockSession2 := entities.Session{
		ID:           "mockSessionID2",
		UserID:       "userID",
		IsAdmin:      false,
		RefreshToken: mock.Anything,

		ExpiresAt: time.Now().Add(time.Hour),

		UserAgent: mock.Anything,
		ClientIP:  mock.Anything,
	}

	RefreshTests := []struct {
		name     string
		runMocks func(*UserAuthMocks)
		Error    error
	}{
		{
			name: "Success:  refreshed token successfully",
			runMocks: func(userAuthMocks *UserAuthMocks) {
				// Validate the refresh token first and extract the session ID and userID
				userAuthMocks.mockJWTService.EXPECT().ValidateJWTToken(userAuthMocks.ctx, mockSession.RefreshToken).Return(mockSession.ID, mockSession.UserID, nil)
				// Fetch the session from Redis by session ID
				userAuthMocks.mockCache.EXPECT().GetSessionByID(userAuthMocks.ctx, mockSession.ID).Return(mockSession, nil)
				// Generate a new token pair for the user
				userAuthMocks.mockJWTService.EXPECT().GenerateTokenPair(userAuthMocks.ctx, mockSession.UserID).Return(newAccessToken, mockSession2.RefreshToken, nil)
				// Create and save a new session for the new refresh token
				userAuthMocks.mockJWTService.EXPECT().CreateSession(userAuthMocks.ctx, mockSession.UserID, mockSession2.RefreshToken, mockSession2.UserAgent, mockSession2.ClientIP).Return(mockSession2, nil)
				userAuthMocks.mockCache.EXPECT().SaveSession(userAuthMocks.ctx, mockSession2).Return(nil)
				// Remove the old session (best-effort, but propagate error)
				userAuthMocks.mockCache.EXPECT().RemoveSessionByID(userAuthMocks.ctx, mock.Anything).Return(nil)

			},
			Error: nil,
		},
		{
			name: "Fail:  ValidateRefreshToken",
			runMocks: func(userAuthMocks *UserAuthMocks) {
				// Validate the refresh token first and extract the session ID and userID
				userAuthMocks.mockJWTService.EXPECT().ValidateJWTToken(userAuthMocks.ctx, mockSession.RefreshToken).Return(mockSession.ID, mockSession.UserID, app_errors.ErrRefreshTokenStolen)
				userAuthMocks.mockLogger.EXPECT().Error(app_errors.ErrRefreshTokenStolen, mock.Anything, mock.Anything, mock.Anything).Once()

			},
			Error: app_errors.ErrRefreshTokenStolen,
		},
		{
			name: "Fail:  GetSessionByID",
			runMocks: func(userAuthMocks *UserAuthMocks) {
				// Validate the refresh token first and extract the session ID and userID
				userAuthMocks.mockJWTService.EXPECT().ValidateJWTToken(userAuthMocks.ctx, mockSession.RefreshToken).Return(mockSession.ID, mockSession.UserID, nil)
				userAuthMocks.mockCache.EXPECT().GetSessionByID(userAuthMocks.ctx, mockSession.ID).Return(mockSession, randomUndefinedError)
				userAuthMocks.mockLogger.EXPECT().Error(app_errors.ErrInternalServerError, mock.Anything, mock.Anything, mock.Anything).Once()
			},
			Error: randomUndefinedError,
		},
		{
			name: "Fail:  session is expired",
			runMocks: func(userAuthMocks *UserAuthMocks) {
				// Validate the refresh token first and extract the session ID and userID
				userAuthMocks.mockJWTService.EXPECT().ValidateJWTToken(userAuthMocks.ctx, entities.Session{}).Return(mock.Anything, mock.Anything, nil)
				// Fetch the session from Redis by session ID
				userAuthMocks.mockCache.EXPECT().GetSessionByID(userAuthMocks.ctx, mock.Anything).Return(entities.Session{}, nil)

				userAuthMocks.mockLogger.EXPECT().Info(app_errors.ErrSessionTimeExpired.Error(), mock.Anything, mock.Anything)

			},
			Error: app_errors.ErrSessionTimeExpired,
		},
		{
			name: "Fail:  session mismatch",
			runMocks: func(userAuthMocks *UserAuthMocks) {

				mutatedSession := mockSession2
				mutatedSession.RefreshToken = "AnotherRefreshToken"
				// Validate the refresh token first and extract the session ID and userID
				userAuthMocks.mockJWTService.EXPECT().ValidateJWTToken(userAuthMocks.ctx, mockSession2.RefreshToken).Return(mockSession2.ID, mockSession2.UserID, nil)
				// Fetch the session from Redis by session ID
				userAuthMocks.mockCache.EXPECT().GetSessionByID(userAuthMocks.ctx, mockSession2.ID).Return(mutatedSession, nil) // Ensure token in session matches provided token
				userAuthMocks.mockLogger.EXPECT().Error(app_errors.ErrRefreshTokenStolen, mock.Anything, mock.Anything, mock.Anything).Once()
			},
			Error: app_errors.ErrRefreshTokenStolen,
		},
		{
			name: "Fail:  UserAgent and ClientIP are unconsistent",
			runMocks: func(userAuthMocks *UserAuthMocks) {

				mutatedSession := mockSession2
				mutatedSession.UserAgent = "AnotherUserAgent"
				// Validate the refresh token first and extract the session ID and userID
				userAuthMocks.mockJWTService.EXPECT().ValidateJWTToken(userAuthMocks.ctx, mockSession2.RefreshToken).Return(mockSession2.ID, mockSession2.UserID, nil)
				// Fetch the session from Redis by session ID
				userAuthMocks.mockCache.EXPECT().GetSessionByID(userAuthMocks.ctx, mockSession2.ID).Return(mutatedSession, nil) // Ensure token in session matches provided token
				// Confirm UserAgent and ClientIP are consistent with the stored session
				userAuthMocks.mockLogger.EXPECT().Error(app_errors.ErrRefreshTokenStolen, mock.Anything, mock.Anything, mock.Anything).Once()
			},
			Error: app_errors.ErrRefreshTokenStolen,
		},
		{
			name: "Fail:  GenerateTokenPair",
			runMocks: func(userAuthMocks *UserAuthMocks) {
				// Validate the refresh token first and extract the session ID and userID
				userAuthMocks.mockJWTService.EXPECT().ValidateJWTToken(userAuthMocks.ctx, mockSession2.RefreshToken).Return(mockSession2.ID, mockSession2.UserID, nil)
				// Fetch the session from Redis by session ID
				userAuthMocks.mockCache.EXPECT().GetSessionByID(userAuthMocks.ctx, mockSession2.ID).Return(mockSession2, nil) // Ensure token in session matches provided token
				userAuthMocks.mockJWTService.EXPECT().GenerateTokenPair(userAuthMocks.ctx, mockSession2.UserID).Return(mock.Anything, mock.Anything, randomUndefinedError)
				userAuthMocks.mockLogger.EXPECT().Error(app_errors.ErrInternalServerError, mock.Anything, mock.Anything, mock.Anything).Once()
			},
			Error: app_errors.ErrInternalServerError,
		},
		{
			name: "Fail:  CreateSession",
			runMocks: func(userAuthMocks *UserAuthMocks) {
				// Validate the refresh token first and extract the session ID and userID
				userAuthMocks.mockJWTService.EXPECT().ValidateJWTToken(userAuthMocks.ctx, mockSession2.RefreshToken).Return(mockSession2.ID, mockSession2.UserID, nil)
				// Fetch the session from Redis by session ID
				userAuthMocks.mockCache.EXPECT().GetSessionByID(userAuthMocks.ctx, mockSession2.ID).Return(mockSession2, nil) // Ensure token in session matches provided token
				userAuthMocks.mockJWTService.EXPECT().GenerateTokenPair(userAuthMocks.ctx, mockSession2.UserID).Return(mock.Anything, mock.Anything, nil)
				// Create and save a new session for the new refresh token
				userAuthMocks.mockJWTService.EXPECT().CreateSession(userAuthMocks.ctx, mockSession2.UserID, mockSession2.RefreshToken, mockSession2.UserAgent, mockSession2.ClientIP).Return(mockSession2, randomUndefinedError)
				userAuthMocks.mockLogger.EXPECT().Error(app_errors.ErrInternalServerError, mock.Anything, mock.Anything, mock.Anything).Once()

			},
			Error: app_errors.ErrInternalServerError,
		},
		{
			name: "Fail:  SaveSession",
			runMocks: func(userAuthMocks *UserAuthMocks) {
				// Validate the refresh token first and extract the session ID and userID
				userAuthMocks.mockJWTService.EXPECT().ValidateJWTToken(userAuthMocks.ctx, mockSession2.RefreshToken).Return(mockSession2.ID, mockSession2.UserID, nil)
				// Fetch the session from Redis by session ID
				userAuthMocks.mockCache.EXPECT().GetSessionByID(userAuthMocks.ctx, mockSession2.ID).Return(mockSession2, nil) // Ensure token in session matches provided token
				userAuthMocks.mockJWTService.EXPECT().GenerateTokenPair(userAuthMocks.ctx, mockSession2.UserID).Return(mock.Anything, mock.Anything, nil)
				// Create and save a new session for the new refresh token
				userAuthMocks.mockJWTService.EXPECT().CreateSession(userAuthMocks.ctx, mockSession2.UserID, mockSession2.RefreshToken, mockSession2.UserAgent, mockSession2.ClientIP).Return(mockSession2, nil)
				userAuthMocks.mockCache.EXPECT().SaveSession(userAuthMocks.ctx, mockSession2).Return(randomUndefinedError)
				userAuthMocks.mockLogger.EXPECT().Error(randomUndefinedError, mock.Anything, mock.Anything, mock.Anything).Once()
			},
			Error: randomUndefinedError,
		},
		{
			name: "Fail:  RemoveSessionByID",
			runMocks: func(userAuthMocks *UserAuthMocks) {
				// Validate the refresh token first and extract the session ID and userID
				userAuthMocks.mockJWTService.EXPECT().ValidateJWTToken(userAuthMocks.ctx, mockSession2.RefreshToken).Return(mockSession2.ID, mockSession2.UserID, nil)
				// Fetch the session from Redis by session ID
				userAuthMocks.mockCache.EXPECT().GetSessionByID(userAuthMocks.ctx, mockSession2.ID).Return(mockSession2, nil) // Ensure token in session matches provided token
				userAuthMocks.mockJWTService.EXPECT().GenerateTokenPair(userAuthMocks.ctx, mockSession2.UserID).Return(mock.Anything, mock.Anything, nil)
				// Create and save a new session for the new refresh token
				userAuthMocks.mockJWTService.EXPECT().CreateSession(userAuthMocks.ctx, mockSession2.UserID, mockSession2.RefreshToken, mockSession2.UserAgent, mockSession2.ClientIP).Return(mockSession2, nil)
				userAuthMocks.mockCache.EXPECT().SaveSession(userAuthMocks.ctx, mockSession2).Return(nil)
				// Remove the old session (best-effort, but propagate error)
				userAuthMocks.mockCache.EXPECT().RemoveSessionByID(userAuthMocks.ctx, mockSession2.ID).Return(randomUndefinedError)
				userAuthMocks.mockLogger.EXPECT().Error(app_errors.ErrInternalServerError, mock.Anything, mock.Anything, mock.Anything)
			},
			Error: app_errors.ErrInternalServerError,
		},
	}

	for _, test := range RefreshTests {
		userAuthMocks := GetNewUserAuthMocks(t)

		test.runMocks(userAuthMocks)

		_, _, err := userAuthMocks.mockUserAuth.Refresh(userAuthMocks.ctx, mock.Anything, mock.Anything, mock.Anything)

		if err == nil {
			assert.NoError(t, err)
		} else {
			assert.Error(t, err)
			assert.True(t, errors.Is(err, test.Error), "Expected: %v  ; but got : %v", test.Error, err)
		}
	}
}

func Test_Logout(t *testing.T) {
	mockSession := entities.Session{
		ID:           "mockSessionID",
		UserID:       "userID",
		IsAdmin:      false,
		RefreshToken: mock.Anything,

		ExpiresAt: time.Now().Add(time.Hour),

		UserAgent: mock.Anything,
		ClientIP:  mock.Anything,
	}

	LogoutTests := []struct {
		name     string
		runMocks func(*UserAuthMocks)
		Error    error
	}{
		{
			name: "Success:  refreshed token successfully",
			runMocks: func(userAuthMocks *UserAuthMocks) {
				userAuthMocks.mockCache.EXPECT().RemoveSessionByID(userAuthMocks.ctx, mockSession.ID).Return(nil)

			},
			Error: nil,
		},
		{
			name: "Fail:  RemoveSessionByID",
			runMocks: func(userAuthMocks *UserAuthMocks) {
				userAuthMocks.mockCache.EXPECT().RemoveSessionByID(userAuthMocks.ctx, mockSession.ID).Return(app_errors.ErrInternalServerError)
				userAuthMocks.mockLogger.EXPECT().Error(app_errors.ErrInternalServerError, mock.Anything, mock.Anything, mock.Anything).Once()

			},
			Error: app_errors.ErrInternalServerError,
		},
	}

	for _, test := range LogoutTests {
		userAuthMocks := GetNewUserAuthMocks(t)

		test.runMocks(userAuthMocks)

		err := userAuthMocks.mockUserAuth.Logout(userAuthMocks.ctx, mockSession.ID)

		if err == nil {
			assert.NoError(t, err)
		} else {
			assert.Error(t, err)
			assert.True(t, errors.Is(err, test.Error), "Expected: %v  ; but got : %v", test.Error, err)
		}
	}
}
