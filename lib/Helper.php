<?php
/**
 * ownCloud - Richdocuments App
 *
 * @author Victor Dubiniuk
 * @copyright 2013 Victor Dubiniuk victor.dubiniuk@gmail.com
 *
 * This file is licensed under the Affero General Public License version 3 or
 * later.
 */

namespace OCA\Richdocuments;

use \DateTime;
use \DateTimeZone;
use OCP\Files\Folder;

class Helper {
	const APP_ID = 'richdocuments';

	/**
	 * @param string $fileId
	 * @return array
	 * @throws \Exception
	 */
	public static function parseFileId($fileId) {
		$arr = explode('_', $fileId);
		if (count($arr) === 1) {
			$fileId = $arr[0];
			$instanceId = '';
			$version = '0';
		} else if (count($arr) === 2) {
			list($fileId, $instanceId) = $arr;
			$version = '0';
		} else if (count($arr) === 3) {
			list($fileId, $instanceId, $version) = $arr;
		} else {
			throw new \Exception('$fileId has not the expected format');
		}

		return [
			$fileId,
			$instanceId,
			$version,
		];
	}

	/**
	 * WOPI helper function to convert to ISO 8601 round-trip format.
	 * @param integer $time Must be seconds since unix epoch
	 */
	public static function toISO8601($time)
	{
		// TODO: Be more precise and don't ignore milli, micro seconds ?
		$datetime = DateTime::createFromFormat('U', $time, new DateTimeZone('UTC'));
		if ($datetime)
			return $datetime->format('Y-m-d\TH:i:s.u\Z');

		return false;
	}

	public static function getNewFileName(Folder $folder, $filename) {
		$fileNum = 1;

		while ($folder->nodeExists($filename)) {
			$fileNum++;
			$filename = preg_replace('/(\.| \(\d+\)\.)([^.]*)$/', ' (' . $fileNum . ').$2', $filename);
		}

		return $filename;
	}

	/**
	 * WOPI helper function to compare 2 locks.
	 * Officially, this should compare to lock string, 
	 * but due to Word online bug, we may compare json['S']
	 */

	 public static function compareLocks(String $lock1, String $lock2) {
		if ($lock1 === $lock2) return true;
		$lck1 = json_decode($lock1);
		if (is_null($lck1)) {
			$lck1 = json_decode(json_encode(array("S" => $lock1)));
		}
		if (!isset($lck1->{'S'})) return false;
		try {
			$lck2 = json_decode($lock2);
			if (is_null($lck2))  {
				$lck2 = json_decode(json_encode(array("S" => $lock2)));
			} 
			return $lck1->{'S'} === $lck2->{'S'}; //used by Word

		} catch (\Exception $e) {
			return false; //whatever
		}

	 }
}
