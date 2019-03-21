<?php
/**
 * @copyright Copyright (c) 2016 Lukas Reschke <lukas@statuscode.ch>
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

namespace OCA\Richdocuments\WOPI;

class Parser {
	/** @var DiscoveryManager */
	private $discoveryManager;

	/**
	 * @param DiscoveryManager $discoveryManager
	 */
	public function __construct(DiscoveryManager $discoveryManager) {
		$this->discoveryManager = $discoveryManager;
	}

	/**
	 * @param $mimetype
	 * @return array
	 * @throws \Exception
	 */
	public function getUrlSrc($mimetype) {
		$discovery = $this->discoveryManager->get();
		$loadEntities = libxml_disable_entity_loader(true);
		$discoveryParsed = simplexml_load_string($discovery);
		$oApp = '';
		libxml_disable_entity_loader($loadEntities);
		

		// $result = $discoveryParsed->xpath(sprintf('/wopi-discovery/net-zone/app[@name=\'%s\']/action', $mimetype));
		switch ($mimetype) {
			case 'application/msword' :
			case 'application/msword' :
			case 'application/vnd.openxmlformats-officedocument.wordprocessingml.document' :
			case 'application/vnd.openxmlformats-officedocument.wordprocessingml.template' :
			case 'application/vnd.ms-word.document.macroEnabled.12' :
			case 'application/vnd.ms-word.template.macroEnabled.12' :
				$oApp = 'Word';
				break;
			
			case 'application/vnd.ms-excel' :
			case 'application/vnd.ms-excel' :
			case 'application/vnd.ms-excel' :
			case 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' :
			case 'application/vnd.openxmlformats-officedocument.spreadsheetml.template' :
			case 'application/vnd.ms-excel.sheet.macroEnabled.12' :
			case 'application/vnd.ms-excel.template.macroEnabled.12' :
			case 'application/vnd.ms-excel.addin.macroEnabled.12' :
			case 'application/vnd.ms-excel.sheet.binary.macroEnabled.12' :
				$oApp = 'Excel';
				break;
		
			case 'application/vnd.ms-powerpoint' :
			case 'application/vnd.ms-powerpoint' :
			case 'application/vnd.ms-powerpoint' :
			case 'application/vnd.ms-powerpoint' :
			case 'application/vnd.openxmlformats-officedocument.presentationml.presentation' :
			case 'application/vnd.openxmlformats-officedocument.presentationml.template' :
			case 'application/vnd.openxmlformats-officedocument.presentationml.slideshow' :
			case 'application/vnd.ms-powerpoint.addin.macroEnabled.12' :
			case 'application/vnd.ms-powerpoint.presentation.macroEnabled.12 ' :
			case 'application/vnd.ms-powerpoint.template.macroEnabled.12' :
			case 'application/vnd.ms-powerpoint.slideshow.macroEnabled.12' :
				$oApp = 'PowerPoint';
				break;
			
			default:
				$oApp = 'Word';
		}
		$result = $discoveryParsed->xpath(sprintf('/wopi-discovery/net-zone/app[@name=\'%s\']/action', $oApp));
		
		if ($result && count($result) > 0) {
			$url = (string)$result[0]['urlsrc'];
			$urlsrc = substr($url, 0, strpos($url, '<'));
			return [
				'urlsrc' => $urlsrc,
				'action' => (string)$result[0]['name'],
			];
		}

		throw new \Exception('Could not find urlsrc in WOPI');

	}

}