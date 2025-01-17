import { ESupportedChains } from "../../helpers/constants";
import { ContractStorage } from "../../helpers/ContractStorage";
import { Deployment } from "../../helpers/Deployment";
import { EContracts, IDeployParams } from "../../helpers/types";

const deployment = Deployment.getInstance();
const storage = ContractStorage.getInstance();

/**
 * Deploy step registration and task itself
 */
deployment
  .deployTask("full:deploy-gatekeepers", "Deploy gatekeepers")
  .setAction(async ({ incremental }: IDeployParams, hre) => {
    deployment.setHre(hre);
    const deployer = await deployment.getDeployer();

    const freeForAllGatekeeperContractAddress = storage.getAddress(EContracts.FreeForAllGatekeeper, hre.network.name);
    const easGatekeeperContractAddress = storage.getAddress(EContracts.EASGatekeeper, hre.network.name);
    const worldIDGatekeeperContractAddress = storage.getAddress(EContracts.WorldIDGatekeeper, hre.network.name);
    const deployFreeForAllGatekeeper = deployment.getDeployConfigField(EContracts.FreeForAllGatekeeper, "deploy");
    const deployEASGatekeeper = deployment.getDeployConfigField(EContracts.EASGatekeeper, "deploy");
    const deployWorldIDGatekeeper = deployment.getDeployConfigField(EContracts.WorldIDGatekeeper, "deploy");

    const skipDeployFreeForAllGatekeeper = deployFreeForAllGatekeeper === false;
    const skipDeployEASGatekeeper = deployEASGatekeeper === false;
    const skipDeployWorldIdGatekeeper = deployWorldIDGatekeeper === false;

    const canSkipDeploy =
      incremental &&
      (freeForAllGatekeeperContractAddress || skipDeployFreeForAllGatekeeper) &&
      (easGatekeeperContractAddress || skipDeployEASGatekeeper) &&
      (worldIDGatekeeperContractAddress || skipDeployWorldIdGatekeeper) &&
      (!skipDeployFreeForAllGatekeeper || !skipDeployEASGatekeeper || !skipDeployWorldIdGatekeeper);

    if (canSkipDeploy) {
      return;
    }

    if (!skipDeployFreeForAllGatekeeper) {
      const freeFroAllGatekeeperContract = await deployment.deployContract(EContracts.FreeForAllGatekeeper, deployer);

      await storage.register({
        id: EContracts.FreeForAllGatekeeper,
        contract: freeFroAllGatekeeperContract,
        args: [],
        network: hre.network.name,
      });
    }

    const isSupportedNetwork = ![ESupportedChains.Hardhat, ESupportedChains.Coverage].includes(
      hre.network.name as ESupportedChains,
    );

    if (!skipDeployEASGatekeeper && isSupportedNetwork) {
      const easAddress = deployment.getDeployConfigField<string>(EContracts.EASGatekeeper, "easAddress", true);
      const encodedSchema = deployment.getDeployConfigField<string>(EContracts.EASGatekeeper, "schema", true);
      const attester = deployment.getDeployConfigField<string>(EContracts.EASGatekeeper, "attester", true);

      const easGatekeeperContract = await deployment.deployContract(
        EContracts.EASGatekeeper,
        deployer,
        easAddress,
        attester,
        encodedSchema,
      );

      await storage.register({
        id: EContracts.EASGatekeeper,
        contract: easGatekeeperContract,
        args: [easAddress, attester, encodedSchema],
        network: hre.network.name,
      });
    }

    if (!skipDeployWorldIdGatekeeper && isSupportedNetwork) {
      const worldIDAddress = deployment.getDeployConfigField<string>(EContracts.WorldIDGatekeeper, "worldIDAddress", true);
      const appID = deployment.getDeployConfigField<string>(EContracts.WorldIDGatekeeper, "appID", true);
      const action = deployment.getDeployConfigField<string>(EContracts.WorldIDGatekeeper, "action", true);

      const worldIDGatekeeperContract = await deployment.deployContract(
        EContracts.WorldIDGatekeeper,
        deployer,
        worldIDAddress,
        appID,
        action,
      );

      await storage.register({
        id: EContracts.WorldIDGatekeeper,
        contract: worldIDGatekeeperContract,
        args: [worldIDAddress, appID, action],
        network: hre.network.name,
      });
    }
  });
