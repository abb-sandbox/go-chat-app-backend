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

func Test_RegisterUser(t *testing.T) {

	var mockUser = entities.User{
		Email:        "example@email.com",
		PasswordHash: []byte("hashhashhashhashhashhashhashhashhashhash"),
	}

	newLinkAsKey := "sdfgsdfgdsfg"

	RegisterUserTests := []struct {
		name       string
		setupMocks func(*UserAuthMocks)
		Error      error
	}{
		{
			name: "Success: User Registrated succesfully ",
			setupMocks: func(mocks *UserAuthMocks) {
				mocks.mockUserRepo.EXPECT().CheckEmailExistence(mocks.ctx, mockUser.Email).Return(nil)
				mocks.mockJWTService.EXPECT().GenerateActivationLink(mocks.ctx).Return(mock.Anything, nil)
				mocks.mockCache.EXPECT().SaveUserInCache(mocks.ctx, newLinkAsKey, mockUser, mocks.mockUserAuth.ActivationTimeExpiry).Return(nil)
				mocks.mockMailingService.EXPECT().SendActivationLink(mocks.ctx, mockUser.Email, newLinkAsKey).Return(nil)

			},
			Error: nil,
		},
		{
			name: "Error : User already exists",
			setupMocks: func(mocks *UserAuthMocks) {
				mocks.mockUserRepo.EXPECT().CheckEmailExistence(mocks.ctx, mockUser.Email).Return(app_errors.ErrUserAlreadyExists)
				mocks.mockLogger.EXPECT().Info(app_errors.ErrUserAlreadyExists.Error(), mock.Anything, mock.Anything).Once()
			},
			Error: app_errors.ErrUserAlreadyExists,
		},
		{
			name: "Error:  Internal server error , mailing is down ",
			setupMocks: func(mocks *UserAuthMocks) {
				mocks.mockUserRepo.EXPECT().CheckEmailExistence(mocks.ctx, mockUser.Email).Return(nil)
				mocks.mockJWTService.EXPECT().GenerateActivationLink(mocks.ctx).Return(mock.Anything, nil)
				mocks.mockCache.EXPECT().SaveUserInCache(mocks.ctx, newLinkAsKey, mockUser, mocks.mockUserAuth.ActivationTimeExpiry).Return(nil)
				mocks.mockMailingService.EXPECT().SendActivationLink(mocks.ctx, mockUser.Email, newLinkAsKey).Return(app_errors.ErrInternalServerError)
				mocks.mockLogger.EXPECT().Error(mock.Anything, mock.Anything, mock.Anything).Once()

			},
			Error: app_errors.ErrInternalServerError,
		},
		{
			name: "Error:  Internal server error , cache is down ",
			setupMocks: func(mocks *UserAuthMocks) {
				mocks.mockUserRepo.EXPECT().CheckEmailExistence(mocks.ctx, mockUser.Email).Return(nil)
				mocks.mockJWTService.EXPECT().GenerateActivationLink(mocks.ctx).Return(mock.Anything, nil)
				mocks.mockCache.EXPECT().SaveUserInCache(mocks.ctx, newLinkAsKey, mockUser, mocks.mockUserAuth.ActivationTimeExpiry).Return(app_errors.ErrInternalServerError)
				mocks.mockLogger.EXPECT().Error(mock.Anything, mock.Anything, mock.Anything).Once()
			},
			Error: app_errors.ErrInternalServerError,
		},
		{
			name: "Error:  Internal server error , user repo is down ",
			setupMocks: func(mocks *UserAuthMocks) {
				mocks.mockUserRepo.EXPECT().CheckEmailExistence(mocks.ctx, mockUser.Email).Return(app_errors.ErrInternalServerError)
				mocks.mockLogger.EXPECT().Error(mock.Anything, mock.Anything, mock.Anything).Once()
			},
			Error: app_errors.ErrInternalServerError,
		},
	}

	for _, val := range RegisterUserTests {

		mocks := GetNewUserAuthMocks(t)

		val.setupMocks(mocks)

		err := mocks.mockUserAuth.Register(mocks.ctx, mockUser)

		if err == nil {
			assert.NoError(t, err)
		} else {
			assert.Error(t, err)
			assert.True(t, errors.Is(err, val.Error), "Expected error: %v, but got : %v", val.Error, err)
		}

	}

}
