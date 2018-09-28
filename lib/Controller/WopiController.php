<?php
/**
 * @copyright Copyright (c) 2016-2017 Lukas Reschke <lukas@statuscode.ch>
 *
 * @license GNU AGPL version 3 or any later version
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

namespace OCA\Richdocuments\Controller;

use OC\Files\View;
use OCA\Richdocuments\Db\WopiMapper;
use OCA\Richdocuments\TokenManager;
use OCA\Richdocuments\Helper;
use OCP\AppFramework\Controller;
use OCP\AppFramework\Db\DoesNotExistException;
use OCP\AppFramework\Http;
use OCP\AppFramework\Http\JSONResponse;
use OCP\Files\File;
use OCP\Files\IRootFolder;
use OCP\IConfig;
use OCP\ILogger;
use OCP\IRequest;
use OCP\IURLGenerator;
use OCP\AppFramework\Http\StreamResponse;
use OCP\IUserManager;
use OCP\IUserSession;

class WopiController extends Controller {
	/** @var IRootFolder */
	private $rootFolder;
	/** @var IURLGenerator */
	private $urlGenerator;
	/** @var IConfig */
	private $config;
	/** @var TokenManager */
	private $tokenManager;
	/** @var IUserManager */
	private $userManager;
	/** @var WopiMapper */
	private $wopiMapper;
	/** @var ILogger */
	private $logger;
	/** @var IUserSession */
	private $userSession;

	/**
	 * @param string $appName
	 * @param string $UserId
	 * @param IRequest $request
	 * @param IRootFolder $rootFolder
	 * @param IURLGenerator $urlGenerator
	 * @param IConfig $config
	 * @param TokenManager $tokenManager
	 * @param IUserManager $userManager
	 * @param WopiMapper $wopiMapper
	 * @param ILogger $logger
	 */
	public function __construct($appName,
								$UserId,
								IRequest $request,
								IRootFolder $rootFolder,
								IURLGenerator $urlGenerator,
								IConfig $config,
								TokenManager $tokenManager,
								IUserManager $userManager,
								WopiMapper $wopiMapper,
								ILogger $logger,
								IUserSession $userSession) {
		parent::__construct($appName, $request);
		$this->rootFolder = $rootFolder;
		$this->urlGenerator = $urlGenerator;
		$this->config = $config;
		$this->tokenManager = $tokenManager;
		$this->userManager = $userManager;
		$this->wopiMapper = $wopiMapper;
		$this->logger = $logger;
		$this->userSession = $userSession;
	}

	/**
	 * Returns general info about a file.
	 *
	 * @NoAdminRequired
	 * @NoCSRFRequired
	 * @PublicPage
	 *
	 * @param string $fileId
	 * @return JSONResponse
	 */
	public function checkFileInfo($fileId) {
		$token = $this->request->getParam('access_token');

		list($fileId, , $version) = Helper::parseFileId($fileId);

		try {
			$wopi = $this->wopiMapper->getPathForToken($token);
		} catch (DoesNotExistException $e) {
			return new JSONResponse([], Http::STATUS_FORBIDDEN);
		}

		// Login the user to see his mount locations
		try {
			/** @var File $file */
			$userFolder = $this->rootFolder->getUserFolder($wopi->getOwnerUid());
			$file = $userFolder->getById($fileId)[0];
		} catch (\Exception $e) {
			return new JSONResponse([], Http::STATUS_FORBIDDEN);
		}

		if(!($file instanceof File)) {
			return new JSONResponse([], Http::STATUS_FORBIDDEN);
		}

		$response = [
			'BaseFileName' => $file->getName(),
			'Size' => $file->getSize(),
			'Version' => $version,
			'UserId' => !is_null($wopi->getEditorUid()) ? $wopi->getEditorUid() : 'guest',
			'SHA256' => base64_encode($file->hash('sha256', true)),
			'OwnerId' => $wopi->getOwnerUid(),
			'UserFriendlyName' => !is_null($wopi->getEditorUid()) ? \OC_User::getDisplayName($wopi->getEditorUid()) : $wopi->getGuestDisplayname(),
			'UserExtraInfo' => [
			],
			'UserCanWrite' => $wopi->getCanwrite(),
			'SupportsCoauth' => true,
			'SupportsLocks' => true,
			'SupportsUpdate' => true,
			'SupportsFileCreation' => true,
			'WebEditingDisabled' => false,
			'ClosePostMessage' => true,
			'CloseUrl' => $wopi->getServerHost(),
			'UserCanNotWriteRelative' => \OC::$server->getEncryptionManager()->isEnabled() ? true : is_null($wopi->getEditorUid()),
			'PostMessageOrigin' => $wopi->getServerHost(),
			// 'LastModifiedTime' => Helper::toISO8601($file->getMTime()),
			// 'EnableInsertRemoteImage' => true,
			// 'EnableShare' => true,
		];


		$serverVersion = $this->config->getSystemValue('version');
		if (version_compare($serverVersion, '13', '>=')) {
			$user = $this->userManager->get($wopi->getEditorUid());
			if($user !== null && $user->getAvatarImage(32) !== null) {
				$response['UserExtraInfo']['avatar'] = $this->urlGenerator->linkToRouteAbsolute('core.avatar.getAvatar', ['userId' => $wopi->getEditorUid(), 'size' => 32]);
			}
		}
		return new JSONResponse($response);
	}

	/**
	 * Given an access token and a fileId, returns the contents of the file.
	 * Expects a valid token in access_token parameter.
	 *
	 * @PublicPage
	 * @NoCSRFRequired
	 *
	 * @param string $fileId
	 * @param string $access_token
	 * @return Http\Response
	 */
	public function getFile($fileId,
							$access_token) {
		list($fileId, , $version) = Helper::parseFileId($fileId);

		$wopi = $this->wopiMapper->getPathForToken($access_token);

		if ((int)$fileId !== $wopi->getFileid()) {
			return new JSONResponse([], Http::STATUS_FORBIDDEN);
		}

		try {
			/** @var File $file */
			$userFolder = $this->rootFolder->getUserFolder($wopi->getOwnerUid());
			$file = $userFolder->getById($fileId)[0];
			\OC_User::setIncognitoMode(true);
			if ($version !== '0') {
				$view = new View('/' . $wopi->getOwnerUid() . '/files');
				$relPath = $view->getRelativePath($file->getPath());
				$versionPath = '/files_versions/' . $relPath . '.v' . $version;
				$view = new View('/' . $wopi->getOwnerUid());
				if ($view->file_exists($versionPath)){
					$response = new StreamResponse($view->fopen($versionPath, 'rb'));
				}
				else {
					return new JSONResponse([], Http::STATUS_NOT_FOUND);
				}
			}
			else
			{
				$response = new StreamResponse($file->fopen('rb'));
			}
			$response->addHeader('Content-Disposition', 'attachment');
			$response->addHeader('Content-Type', 'application/octet-stream');
			return $response;
		} catch (\Exception $e) {
			return new JSONResponse([], Http::STATUS_FORBIDDEN);
		}
	}

	/**
	 * Given an access token and a fileId, replaces the files with the request body.
	 * Expects a valid token in access_token parameter.
	 *
	 * @PublicPage
	 * @NoCSRFRequired
	 *
	 * @param string $fileId
	 * @param string $access_token
	 * @return JSONResponse
	 */
	public function putFile($fileId,
							$access_token) {
		list($fileId, ,) = Helper::parseFileId($fileId);
		$isPutRelative = ($this->request->getHeader('X-WOPI-Override') === 'PUT_RELATIVE');

		$wopi = $this->wopiMapper->getPathForToken($access_token);
		if (!$wopi->getCanwrite()) {
			return new JSONResponse([], Http::STATUS_FORBIDDEN);
		}

		// Unless the editor is empty (public link) we modify the files as the current editor
		$editor = $wopi->getEditorUid();
		if ($editor === null) {
			$editor = $wopi->getOwnerUid();
		}

		try {
			/** @var File $file */
			$userFolder = $this->rootFolder->getUserFolder($editor);
			$file = $userFolder->getById($fileId)[0];
			//Create a lock file
			$lockFilePath = '.' . $file->getName() . '.lock';
			if (!$file->getParent()->nodeExists($lockFilePath)) {
				$lockFile = $file->getParent()->newFile($lockFilePath);
				$this->logger->debug('Lock file {lf} created', ['lf' => $lockFilePath]);
			} else {
				$lockFile = $file->getParent()->get($lockFilePath);
				$this->logger->debug('Lock file {lf} exists', ['lf' => $lockFilePath]);
			}

			$this->logger->debug("Lock action is: {err}", ['err' => $this->request->getHeader('X-WOPI-Override')]);
			$this->logger->debug("Lock status is: {err}", ['err' => $this->request->getHeader('X-WOPI-Lock')]);
			$this->logger->debug("OldLock status is: {err}", ['err' => $this->request->getHeader('X-WOPI-OldLock')]);

			//Lock file if requested
			if ($this->request->getHeader('X-WOPI-Override') === 'LOCK') {
				try {
					$cLf = $lockFile->getContent();
					$lockID = $this->request->getHeader('X-WOPI-Lock');
					// $oldLockID = $this->request->getHeader('X-WOPI-OldLock');
					if (strlen($cLf) === 0) {
						$lockFile->putContent($lockID);
						return new JSONResponse([], Http::STATUS_OK);
					} else if (Helper::compareLocks($cLf, $lockID)) {
						return new JSONResponse([], Http::STATUS_OK);
					} else {
						$this->logger->debug("Lock exception: Already lock by {err}", ['err' => $cLf]);
						$response = new JSONResponse([], Http::STATUS_CONFLICT);
						$response->addHeader('X-WOPI-Lock', $cLf);
						return $response;
					}
				} catch (\Exception $e) {
					$response = new JSONResponse([], Http::STATUS_CONFLICT);
					$response->addHeader('X-WOPI-LockFailureReason', $e);
					$response->addHeader('X-WOPI-Lock', $cLf);
					$this->logger->debug("Lock exception: {err}", ['err' => $e]);
					return $response;
				}
			}
			if ($this->request->getHeader('X-WOPI-Override') === 'REFRESH_LOCK') {
				try {
					$cLf= $lockFile->getContent();
					$lockID = $this->request->getHeader('X-WOPI-Lock');
					if (Helper::compareLocks($cLf, $lockID)) {
						return new JSONResponse([], Http::STATUS_OK);
					} else {
						$response = new JSONResponse([], Http::STATUS_CONFLICT);
						$response->addHeader('X-WOPI-Lock', $cLf);
						return $response;
					}
				} catch (\Exception $e) {
					$response = new JSONResponse([], Http::STATUS_CONFLICT);
					$response->addHeader('X-WOPI-LockFailureReason', $e);
					$response->addHeader('X-WOPI-Lock', $cLf);
					$this->logger->debug("Lock exception: {err}", ['err' => $e]);
					return $response;
				}
			}
			//Unlock file
			if ($this->request->getHeader('X-WOPI-Override') === 'UNLOCK') {
				try {
					if (!$file->getParent()->nodeExists($lockFilePath)) {
						return new JSONResponse([], Http::STATUS_OK);
					}
					$cLf = $lockFile->getContent();
					$lockID = $this->request->getHeader('X-WOPI-Lock');
					
					if (Helper::compareLocks($cLf, $lockID)) {
						$lockFile->putContent('');
						return new JSONResponse([], Http::STATUS_OK);
					} else {
						$this->logger->debug("Unlock exception: unlock Failed, {err1} mismatch {err2}", ['err1' => $cLf, 'err2'=> $lockID]);
						$response = new JSONResponse([], Http::STATUS_CONFLICT);
						$response->addHeader('X-WOPI-Lock', $cLf);
						return $response;
					}
				} catch (\Exception $e) {
					$response = new JSONResponse([], Http::STATUS_CONFLICT);
					$response->addHeader('X-WOPI-LockFailureReason', $e);
					$response->addHeader('X-WOPI-Lock', $cLf);
					$this->logger->debug("Unlock exception: {err}", ['err' => $e]);
					return $response;
				}
			}

			if ($isPutRelative) {
				// the new file needs to be installed in the current user dir
				$userFolder = $this->rootFolder->getUserFolder($wopi->getEditorUid());
				$file = $userFolder->getById($fileId)[0];

				$target = $this->request->getHeader('X-WOPI-RelativeTarget');
				$target = iconv('utf-7', 'utf-8', $target);
				$this->logger->debug("RelativeTarget is: {err}", ['err' => $target]);

				if (!$target) {
					$target = $this->request->getHeader('X-WOPI-SuggestedTarget');
					$target = iconv('utf-7', 'utf-8', $target);
				} else {
					if ($this->request->getHeader('X-WOPI-SuggestedTarget')) {
						return new JSONResponse([], Http::STATUS_BAD_REQUEST);
					}
				}

				try {
					if($this->request->getHeader('X-WOPI-OverwriteRelativeTarget')) {
						$file = $file->getParent()->get($target);
					} else {
						$file = $file->getParent()->newFile($target);
					}
				} catch (\Exception $e) {
					return new JSONResponse([], Http::STATUS_BAD_REQUEST);
				}
			}

			$content = fopen('php://input', 'rb');

			// Set the user to register the change under his name
			$editor = $this->userManager->get($wopi->getEditorUid());
			if (!is_null($editor)) {
				$this->userSession->setUser($editor);
			}

			// $this->logger->debug('{content}', ['content' => $content]);
			if ($this->request->getHeader('X-WOPI-Override') === 'PUT') {
				$file->putContent($content);
				return new JSONResponse([], Http::STATUS_OK);
			} elseif ($isPutRelative) {
				// generate a token for the new file (the user still has to be
				// logged in)
				$this->logger->debug("File is: {err}", ['err' => $file]);

				$file->putContent($content);
				list(, $wopiToken) = $this->tokenManager->getToken($file->getId(), null, $wopi->getEditorUid());

				$wopi = 'index.php/apps/richdocuments/wopi/files/' . $file->getId() . '_' . $this->config->getSystemValue('instanceid') . '?access_token=' . $wopiToken;
				$url = $this->urlGenerator->getAbsoluteURL($wopi);

				return new JSONResponse([ 'Name' => $file->getName(), 'Url' => $url ], Http::STATUS_OK);
			} else {
				$this->logger->debug("Unlock exception: Unknown action");

				return new JSONResponse([], Http::STATUS_NOT_IMPLEMENTED);
			}

		} catch (\Exception $e) {
			$this->logger->debug("UnExpected exception: {err}", ['err' => $e]);
			return new JSONResponse([], Http::STATUS_INTERNAL_SERVER_ERROR);
		}
	}

	/**
	 * Given an access token and a fileId, replaces the files with the request body.
	 * Expects a valid token in access_token parameter.
	 * Just actually routes to the PutFile, the implementation of PutFile
	 * handles both saving and saving as.* Given an access token and a fileId, replaces the files with the request body.
	 *
	 * @PublicPage
	 * @NoCSRFRequired
	 *
	 * @param string $fileId
	 * @param string $access_token
	 * @return JSONResponse
	 */
	public function putRelativeFile($fileId,
					$access_token) {
		return $this->putFile($fileId, $access_token);
	}
}
